package app

import (
	"path/filepath"
	"testing"
)

func newApp(t *testing.T) (*App, string) {
	p := filepath.Join(t.TempDir(), "settings.json")
	return New(p), p
}

func importThree(t *testing.T, a *App) []string {
	res := a.Import("ss://YWVzLTI1Ni1nY206cHc=@1.1.1.1:8388#a\nss://YWVzLTI1Ni1nY206cHc=@2.2.2.2:8388#b\nss://YWVzLTI1Ni1nY206cHc=@3.3.3.3:8388#c")
	if res.Added != 3 {
		t.Fatalf("импорт: %+v", res)
	}
	return res.IDs
}

func ids(a *App, view string) map[string]bool {
	m := map[string]bool{}
	for _, id := range a.ViewIDs(view) {
		m[id] = true
	}
	return m
}

func TestGroupsMoveAndViews(t *testing.T) {
	a, _ := newApp(t)
	id := importThree(t, a)
	if err := a.AddGroup("Работа"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "  ", "Корзина", "общий", "Работа", "работа"} {
		if a.AddGroup(bad) == nil {
			t.Errorf("название %q должно отклоняться", bad)
		}
	}
	if err := a.MoveToGroup([]string{id[0], id[1]}, "Работа"); err != nil {
		t.Fatal(err)
	}
	if a.MoveToGroup([]string{id[2]}, "Нет такой") == nil {
		t.Error("перенос в несуществующую вкладку")
	}
	if m := ids(a, GroupView("Работа")); len(m) != 2 || !m[id[0]] || !m[id[1]] {
		t.Errorf("вкладка Работа: %v", m)
	}
	if m := ids(a, ViewMain); len(m) != 1 || !m[id[2]] {
		t.Errorf("общий список: %v", m)
	}
	// отмеченные видны на «Активных» независимо от вкладки
	a.Select(id[0], true)
	a.Select(id[2], true)
	if m := ids(a, ViewActive); len(m) != 2 || !m[id[0]] || !m[id[2]] {
		t.Errorf("активные: %v", m)
	}
	// переименование переносит серверы
	if err := a.RenameGroup("Работа", "Офис"); err != nil {
		t.Fatal(err)
	}
	if len(ids(a, GroupView("Офис"))) != 2 || len(ids(a, GroupView("Работа"))) != 0 {
		t.Error("переименование")
	}
	// удаление вкладки возвращает серверы в общий список
	if err := a.DeleteGroup("Офис"); err != nil {
		t.Fatal(err)
	}
	if len(ids(a, ViewMain)) != 3 || len(a.Groups()) != 0 {
		t.Error("удаление вкладки")
	}
}

func TestTrashRestoreAndForever(t *testing.T) {
	a, _ := newApp(t)
	id := importThree(t, a)
	_ = a.AddGroup("G")
	_ = a.MoveToGroup([]string{id[0]}, "G")
	a.Select(id[0], true)

	if err := a.Trash([]string{id[0], id[1]}); err != nil {
		t.Fatal(err)
	}
	if m := ids(a, ViewTrash); len(m) != 2 {
		t.Errorf("корзина: %v", m)
	}
	if len(ids(a, ViewAll)) != 1 || len(ids(a, ViewMain)) != 1 || len(ids(a, GroupView("G"))) != 0 || len(ids(a, ViewActive)) != 0 {
		t.Error("удалённые не должны быть видны на других вкладках, отметка снимается")
	}
	// окончательно удалить можно только то, что в корзине
	if n := a.DeleteForever([]string{id[2]}); n != 0 {
		t.Error("сервер вне корзины не должен удаляться окончательно")
	}
	// восстановление возвращает на прежнюю вкладку
	a.Restore([]string{id[0]})
	if m := ids(a, GroupView("G")); !m[id[0]] {
		t.Error("восстановление на прежнюю вкладку")
	}
	// если вкладку удалили, пока сервер лежал в корзине, — в общий список
	_ = a.Trash([]string{id[0]})
	_ = a.DeleteGroup("G")
	a.Restore([]string{id[0]})
	if m := ids(a, ViewMain); !m[id[0]] {
		t.Error("восстановление при удалённой вкладке")
	}
	if n := a.EmptyTrash(); n != 1 {
		t.Errorf("очистка корзины: %d", n)
	}
	if len(ids(a, ViewTrash)) != 0 || len(ids(a, ViewAll)) != 2 {
		t.Error("после очистки")
	}
}

func TestRecheckScope(t *testing.T) {
	a, _ := newApp(t)
	importThree(t, a)
	if a.Recheck(ViewTrash) == nil {
		t.Error("корзина не проверяется")
	}
	if a.Recheck(GroupView("пусто")) == nil {
		t.Error("пустая вкладка")
	}
	if a.Recheck(ViewActive) == nil {
		t.Error("нет отмеченных")
	}
}

func TestStatePersists(t *testing.T) {
	a, path := newApp(t)
	id := importThree(t, a)
	_ = a.AddGroup("G")
	_ = a.MoveToGroup([]string{id[0]}, "G")
	_ = a.Trash([]string{id[1]})
	a.Select(id[2], true)

	b := New(path)
	if len(b.Groups()) != 1 || !ids(b, GroupView("G"))[id[0]] || !ids(b, ViewTrash)[id[1]] || !ids(b, ViewActive)[id[2]] {
		t.Errorf("после перезапуска состояние потеряно: groups=%v", b.Groups())
	}
}

func TestScanApplyKeepsGroupsAndTrash(t *testing.T) {
	a, _ := newApp(t)
	id := importThree(t, a)
	_ = a.AddGroup("G")
	_ = a.MoveToGroup([]string{id[0]}, "G")
	_ = a.Trash([]string{id[1]})
	// результаты скана: id[0] мёртв, id[1] (в корзине) мёртв, id[2] мёртв и не отмечен
	a.mu.Lock()
	var nodes []Row
	for _, r := range a.rows {
		nodes = append(nodes, *r)
	}
	a.mu.Unlock()
	_ = nodes
	// мёртвые строки на вкладке и в корзине не теряются, а «ничьи» мёртвые удаляются
	a.mu.Lock()
	var res []engineResult
	for _, r := range a.rows {
		res = append(res, engineResult{r.node, false})
	}
	a.mu.Unlock()
	a.applyResults(toEngine(res))
	if !ids(a, GroupView("G"))[id[0]] {
		t.Error("сервер на пользовательской вкладке не должен пропадать при скане")
	}
	if !ids(a, ViewTrash)[id[1]] {
		t.Error("сервер в корзине не должен пропадать при скане")
	}
}
