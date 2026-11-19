package app

import (
	"fmt"
	"strings"

	"proxycheck/internal/node"
	"proxycheck/internal/settings"
)

// Виды (вкладки) списка серверов.
const (
	ViewAll    = "all"    // все, кроме корзины (для веб-интерфейса без вкладок)
	ViewMain   = "main"   // общий список: серверы вне пользовательских вкладок
	ViewActive = "active" // отмеченные галочкой, из любых вкладок
	ViewTrash  = "trash"  // корзина
)

// GroupView возвращает вид для пользовательской вкладки.
func GroupView(name string) string { return "g:" + name }

// Reserved — имена, которые нельзя дать пользовательской вкладке.
var reservedNames = map[string]bool{"общий": true, "активные": true, "корзина": true, "все": true}

// MatchView сообщает, входит ли строка в вид.
func MatchView(r Row, view string) bool {
	if view == ViewTrash {
		return r.Trashed
	}
	if r.Trashed {
		return false
	}
	switch {
	case view == ViewAll:
		return true
	case view == ViewActive:
		return r.Selected
	case view == ViewMain:
		return r.Group == ""
	case strings.HasPrefix(view, "g:"):
		return r.Group == view[2:]
	}
	return false
}

// ViewIDs возвращает ID серверов вида.
func (a *App) ViewIDs(view string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var ids []string
	for _, r := range a.rows {
		if MatchView(*r, view) {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// Groups возвращает пользовательские вкладки в порядке создания.
func (a *App) Groups() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.settings.Groups...)
}

func validGroupName(name string, existing []string, except string) error {
	n := strings.TrimSpace(name)
	switch {
	case n == "":
		return fmt.Errorf("введите название вкладки")
	case len([]rune(n)) > 40:
		return fmt.Errorf("название слишком длинное (максимум 40 символов)")
	case reservedNames[strings.ToLower(n)]:
		return fmt.Errorf("название «%s» зарезервировано", n)
	}
	for _, g := range existing {
		if strings.EqualFold(g, n) && g != except {
			return fmt.Errorf("вкладка «%s» уже есть", g)
		}
	}
	return nil
}

// AddGroup создаёт пользовательскую вкладку.
func (a *App) AddGroup(name string) error {
	name = strings.TrimSpace(name)
	a.mu.Lock()
	if err := validGroupName(name, a.settings.Groups, ""); err != nil {
		a.mu.Unlock()
		return err
	}
	a.settings.Groups = append(a.settings.Groups, name)
	st := a.settings
	a.mu.Unlock()
	return settings.Save(a.path, st)
}

// RenameGroup переименовывает вкладку вместе с её серверами.
func (a *App) RenameGroup(oldName, newName string) error {
	newName = strings.TrimSpace(newName)
	a.mu.Lock()
	idx := -1
	for i, g := range a.settings.Groups {
		if g == oldName {
			idx = i
		}
	}
	if idx < 0 {
		a.mu.Unlock()
		return fmt.Errorf("вкладка не найдена")
	}
	if err := validGroupName(newName, a.settings.Groups, oldName); err != nil {
		a.mu.Unlock()
		return err
	}
	a.settings.Groups[idx] = newName
	for _, r := range a.rows {
		if r.Group == oldName {
			r.Group = newName
		}
	}
	a.mu.Unlock()
	a.save()
	return nil
}

// DeleteGroup удаляет вкладку; её серверы возвращаются в общий список.
func (a *App) DeleteGroup(name string) error {
	a.mu.Lock()
	idx := -1
	for i, g := range a.settings.Groups {
		if g == name {
			idx = i
		}
	}
	if idx < 0 {
		a.mu.Unlock()
		return fmt.Errorf("вкладка не найдена")
	}
	a.settings.Groups = append(a.settings.Groups[:idx], a.settings.Groups[idx+1:]...)
	for _, r := range a.rows {
		if r.Group == name {
			r.Group = ""
		}
	}
	a.mu.Unlock()
	a.save()
	return nil
}

// MoveToGroup переносит серверы на вкладку group ("" — в общий список).
func (a *App) MoveToGroup(ids []string, group string) error {
	a.mu.Lock()
	if group != "" {
		ok := false
		for _, g := range a.settings.Groups {
			if g == group {
				ok = true
			}
		}
		if !ok {
			a.mu.Unlock()
			return fmt.Errorf("вкладка «%s» не найдена", group)
		}
	}
	for _, id := range ids {
		if r, ok := a.find(id); ok && !r.Trashed {
			r.Group = group
		}
	}
	a.mu.Unlock()
	a.save()
	return nil
}

// Trash отправляет серверы в корзину (линии на них останавливаются, отметка снимается).
func (a *App) Trash(ids []string) error {
	for _, id := range ids {
		a.mu.Lock()
		r, ok := a.find(id)
		running := ok && r.Running
		a.mu.Unlock()
		if running {
			if err := a.StopLine(id); err != nil {
				return err
			}
		}
	}
	a.mu.Lock()
	for _, id := range ids {
		if r, ok := a.find(id); ok {
			r.Trashed, r.Selected = true, false
		}
	}
	a.refreshPoolLocked()
	a.mu.Unlock()
	a.save()
	return nil
}

// Restore возвращает серверы из корзины на их прежнюю вкладку.
func (a *App) Restore(ids []string) {
	a.mu.Lock()
	groups := map[string]bool{}
	for _, g := range a.settings.Groups {
		groups[g] = true
	}
	for _, id := range ids {
		if r, ok := a.find(id); ok && r.Trashed {
			r.Trashed = false
			if r.Group != "" && !groups[r.Group] {
				r.Group = ""
			}
		}
	}
	a.refreshPoolLocked()
	a.mu.Unlock()
	a.save()
}

// DeleteForever окончательно удаляет серверы, лежащие в корзине.
func (a *App) DeleteForever(ids []string) int {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	a.mu.Lock()
	rows := a.rows[:0:0]
	n := 0
	for _, r := range a.rows {
		if want[r.ID] && r.Trashed {
			n++
			continue
		}
		rows = append(rows, r)
	}
	a.rows = rows
	a.mu.Unlock()
	a.save()
	return n
}

// EmptyTrash окончательно удаляет всё содержимое корзины.
func (a *App) EmptyTrash() int { return a.DeleteForever(a.ViewIDs(ViewTrash)) }

// setBusy помечает строки серверов «занятыми» (check | speed | queued | "").
func (a *App) setBusy(nodes []node.Node, state string) {
	a.mu.Lock()
	for _, n := range nodes {
		if r, ok := a.find(n.ID()); ok {
			r.Busy = state
		}
	}
	a.mu.Unlock()
}

// refreshPoolLocked пересчитывает резерв для замены упавших серверов:
// живые серверы вне корзины. Вызывать под a.mu.
func (a *App) refreshPoolLocked() {
	var pool []node.Node
	for _, r := range a.rows {
		if r.Status == StatusAlive && !r.Trashed {
			pool = append(pool, r.node)
		}
	}
	a.mgr.SetPool(pool)
}
