//go:build windows

package winui

import (
	"fmt"
	"strings"

	"github.com/tailscale/walk"
	. "github.com/tailscale/walk/declarative"

	"proxycheck/internal/app"
)

// viewState — вкладки списка серверов: «Общий», пользовательские, «Активные», «Корзина».
type viewState struct {
	keys       []string // ключи видов в порядке вкладок
	titles     []string // показанные заголовки
	groups     []string
	rebuilding bool

	newBtn, renameBtn, delBtn *walk.PushButton
	restoreBtn, foreverBtn    *walk.PushButton
	emptyBtn                  *walk.PushButton

	// контекстное меню таблицы серверов
	act  struct{ start, stop, check, speed, edit, cfg, copy, trash, restore, forever, move *walk.Action }
	seps []*walk.Action
	move *walk.Menu
}

func viewKeysFor(groups []string) []string {
	keys := []string{app.ViewMain}
	for _, g := range groups {
		keys = append(keys, app.GroupView(g))
	}
	return append(keys, app.ViewActive, app.ViewTrash)
}

func baseTitle(key string) string {
	switch key {
	case app.ViewMain:
		return "Общий"
	case app.ViewActive:
		return "Активные"
	case app.ViewTrash:
		return "Корзина"
	}
	return strings.TrimPrefix(key, "g:")
}

func isGroupView(key string) bool { return strings.HasPrefix(key, "g:") }

// curView — ключ выбранной вкладки.
func (u *ui) curView() string {
	i := u.viewTabs.CurrentIndex()
	if i < 0 || i >= len(u.views.keys) {
		return app.ViewMain
	}
	return u.views.keys[i]
}

// syncViews приводит набор вкладок и их подписи (с числом серверов) в соответствие
// с данными. Выбранная вкладка сохраняется.
func (u *ui) syncViews(groups []string) {
	v := &u.views
	keys := viewKeysFor(groups)
	cur := u.curView()

	if !equalStrings(keys, v.keys) {
		v.rebuilding = true
		pages := u.viewTabs.Pages()
		_ = pages.Clear()
		v.titles = nil
		for _, k := range keys {
			p, err := walk.NewTabPage()
			if err != nil {
				continue
			}
			_ = p.SetTitle(baseTitle(k))
			_ = pages.Add(p)
			v.titles = append(v.titles, baseTitle(k))
		}
		v.keys, v.groups = keys, append([]string(nil), groups...)
		idx := 0
		for i, k := range keys {
			if k == cur {
				idx = i
			}
		}
		_ = u.viewTabs.SetCurrentIndex(idx)
		v.rebuilding = false
		u.onViewChanged()
		u.rebuildMoveMenu()
	}
	for i, k := range v.keys {
		t := fmt.Sprintf("%s (%d)", baseTitle(k), u.rm.Count(k))
		if i < len(v.titles) && v.titles[i] != t {
			if p := u.viewTabs.Pages().At(i); p != nil {
				_ = p.SetTitle(t)
				v.titles[i] = t
			}
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (u *ui) onViewChanged() {
	if u.views.rebuilding {
		return
	}
	u.rm.SetView(u.curView())
	u.updateViewButtons()
	u.rebuildMoveMenu()
	u.selectionChanged()
}

// updateViewButtons включает кнопки, применимые к текущей вкладке.
func (u *ui) updateViewButtons() {
	v := &u.views
	cur := u.curView()
	group := isGroupView(cur)
	trash := cur == app.ViewTrash
	v.renameBtn.SetEnabled(group)
	v.delBtn.SetEnabled(group)
	v.restoreBtn.SetEnabled(trash)
	v.foreverBtn.SetEnabled(trash)
	v.emptyBtn.SetEnabled(trash)
	u.recheckBtn.SetEnabled(!u.busy && cur != app.ViewTrash)
}

// prompt спрашивает одну строку у пользователя.
func (u *ui) prompt(title, label, initial string) (string, bool) {
	var dlg *walk.Dialog
	var le *walk.LineEdit
	ok := false
	if err := (Dialog{
		AssignTo: &dlg, Title: title, MinSize: Size{Width: 360, Height: 130}, Layout: VBox{},
		Children: []Widget{
			Label{Text: label},
			LineEdit{AssignTo: &le, Text: initial},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				HSpacer{},
				PushButton{Text: "OK", OnClicked: func() { ok = true; dlg.Close(0) }},
				PushButton{Text: "Отмена", OnClicked: func() { dlg.Close(0) }},
			}},
		},
	}).Create(u.mw); err != nil {
		u.fail(err)
		return "", false
	}
	_ = le.SetFocus()
	dlg.Run()
	return strings.TrimSpace(le.Text()), ok
}

func (u *ui) addGroup() {
	name, ok := u.prompt("Новая вкладка", "Название вкладки:", "")
	if !ok {
		return
	}
	if err := u.a.AddGroup(name); err != nil {
		u.fail(err)
		return
	}
	u.refreshNow()
	u.selectView(app.GroupView(name))
}

func (u *ui) renameGroup() {
	cur := u.curView()
	if !isGroupView(cur) {
		return
	}
	old := strings.TrimPrefix(cur, "g:")
	name, ok := u.prompt("Переименовать вкладку", "Новое название:", old)
	if !ok || name == old {
		return
	}
	if err := u.a.RenameGroup(old, name); err != nil {
		u.fail(err)
		return
	}
	u.refreshNow()
	u.selectView(app.GroupView(name))
}

func (u *ui) deleteGroup() {
	cur := u.curView()
	if !isGroupView(cur) {
		return
	}
	name := strings.TrimPrefix(cur, "g:")
	if walk.MsgBox(u.mw, "proxycheck", "Удалить вкладку «"+name+"»? Серверы вернутся в общий список.", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	if err := u.a.DeleteGroup(name); err != nil {
		u.fail(err)
		return
	}
	u.refreshNow()
	u.selectView(app.ViewMain)
}

func (u *ui) selectView(key string) {
	for i, k := range u.views.keys {
		if k == key {
			_ = u.viewTabs.SetCurrentIndex(i)
			return
		}
	}
}

// refreshNow сразу перечитывает состояние (не дожидаясь очередного опроса).
func (u *ui) refreshNow() { u.apply(u.a.Snapshot()) }

func (u *ui) restoreSelected() {
	if ids := idsOf(u.selectedRows()); len(ids) > 0 {
		u.a.Restore(ids)
		u.refreshNow()
	}
}

func (u *ui) forgetSelected() {
	rows := u.selectedRows()
	if len(rows) == 0 {
		return
	}
	if walk.MsgBox(u.mw, "proxycheck", fmt.Sprintf("Удалить окончательно серверов: %d? Это нельзя отменить.", len(rows)), walk.MsgBoxYesNo|walk.MsgBoxIconWarning) != walk.DlgCmdYes {
		return
	}
	u.a.DeleteForever(idsOf(rows))
	u.refreshNow()
}

func (u *ui) emptyTrash() {
	n := u.rm.Count(app.ViewTrash)
	if n == 0 {
		return
	}
	if walk.MsgBox(u.mw, "proxycheck", fmt.Sprintf("Очистить корзину (серверов: %d)? Это нельзя отменить.", n), walk.MsgBoxYesNo|walk.MsgBoxIconWarning) != walk.DlgCmdYes {
		return
	}
	u.a.EmptyTrash()
	u.refreshNow()
}

// ---------- контекстное меню таблицы серверов ----------

func (u *ui) setupMenu() {
	v := &u.views
	menu := u.tv.ContextMenu()
	add := func(text string, f func()) *walk.Action {
		a := walk.NewAction()
		_ = a.SetText(text)
		a.Triggered().Attach(f)
		_ = menu.Actions().Add(a)
		return a
	}
	sep := func() {
		s := walk.NewSeparatorAction()
		_ = menu.Actions().Add(s)
		v.seps = append(v.seps, s)
	}
	v.act.start = add("Запустить линию", u.startSelected)
	v.act.stop = add("Остановить линию", u.stopSelected)
	v.act.check = add("Проверить", u.checkSelected)
	v.act.speed = add("Замерить скорость", u.speedSelected)
	sep()
	v.act.edit = add("Редактировать…", u.editSelected)
	v.act.cfg = add("Конфиг…", u.configSelected)
	v.act.copy = add("Копировать ссылку", u.copySelected)
	sep()
	v.move, _ = walk.NewMenu()
	v.act.move = walk.NewMenuAction(v.move)
	_ = v.act.move.SetText("Переместить на вкладку")
	_ = menu.Actions().Add(v.act.move)
	sep()
	v.act.trash = add("Удалить в корзину", u.trashSelected)
	v.act.restore = add("Восстановить", u.restoreSelected)
	v.act.forever = add("Удалить окончательно…", u.forgetSelected)
	u.rebuildMoveMenu()
	u.selectionChanged()
}

// rebuildMoveMenu пересобирает подменю «Переместить на вкладку».
func (u *ui) rebuildMoveMenu() {
	v := &u.views
	if v.move == nil {
		return
	}
	_ = v.move.Actions().Clear()
	cur := u.curView()
	addTarget := func(title, group string, key string) {
		if key == cur {
			return
		}
		a := walk.NewAction()
		_ = a.SetText(title)
		g := group
		a.Triggered().Attach(func() { u.moveSelected(g) })
		_ = v.move.Actions().Add(a)
	}
	addTarget("Общий", "", app.ViewMain)
	for _, g := range v.groups {
		addTarget(g, g, app.GroupView(g))
	}
	if len(v.groups) == 0 {
		hint := walk.NewAction()
		_ = hint.SetText("(создайте вкладку кнопкой «Новая вкладка»)")
		hint.SetEnabled(false)
		_ = v.move.Actions().Add(hint)
	}
}

func (u *ui) moveSelected(group string) {
	ids := idsOf(u.selectedRows())
	if len(ids) == 0 {
		return
	}
	if err := u.a.MoveToGroup(ids, group); err != nil {
		u.fail(err)
		return
	}
	u.refreshNow()
}

func (u *ui) trashSelected() {
	rows := u.selectedRows()
	if len(rows) == 0 {
		return
	}
	if err := u.a.Trash(idsOf(rows)); err != nil {
		u.fail(err)
		return
	}
	u.refreshNow()
}

// updateMenu показывает в меню только применимые к выделению пункты.
func (u *ui) updateMenu(rows []app.Row) {
	v := &u.views
	if v.act.start == nil {
		return
	}
	trash := u.curView() == app.ViewTrash
	any := len(rows) > 0
	one := len(rows) == 1
	canStart, canStop := false, false
	for _, r := range rows {
		if r.Running {
			canStop = true
		} else if r.Status == app.StatusAlive {
			canStart = true
		}
	}
	vis := func(a *walk.Action, on bool) { a.SetVisible(on) }
	vis(v.act.start, !trash && canStart)
	vis(v.act.stop, !trash && canStop)
	vis(v.act.check, !trash && any)
	vis(v.act.speed, !trash && any)
	vis(v.act.edit, !trash && one)
	vis(v.act.cfg, one)
	vis(v.act.copy, any)
	vis(v.act.move, !trash && any)
	vis(v.act.trash, !trash && any)
	vis(v.act.restore, trash && any)
	vis(v.act.forever, trash && any)
	for _, s := range v.seps {
		s.SetVisible(any)
	}
}
