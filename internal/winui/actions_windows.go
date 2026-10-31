//go:build windows

package winui

import (
	"fmt"
	"strings"

	"github.com/tailscale/walk"
	. "github.com/tailscale/walk/declarative"

	"proxycheck/internal/app"
)

// selectedRows возвращает строки, выделенные в таблице серверов.
func (u *ui) selectedRows() []app.Row {
	var out []app.Row
	for _, i := range u.tv.SelectedIndexes() {
		if i >= 0 && i < len(u.rm.rows) {
			out = append(out, u.rm.rows[i])
		}
	}
	return out
}

// selectionChanged включает в меню только применимые пункты.
func (u *ui) selectionChanged() {
	rows := u.selectedRows()
	canStart, canStop := false, false
	for _, r := range rows {
		if r.Running {
			canStop = true
		} else if r.Status == app.StatusAlive {
			canStart = true
		}
	}
	u.showDetail()
	if u.ctxActs.start != nil {
		u.ctxActs.start.SetVisible(canStart)
		u.ctxActs.stop.SetVisible(canStop)
	}
}

func (u *ui) async(f func() error) {
	go func() {
		err := f()
		u.mw.Synchronize(func() { u.fail(err) })
	}()
}

func (u *ui) startOrStop() {
	rows := u.selectedRows()
	if len(rows) != 1 {
		return
	}
	if rows[0].Running {
		u.stopSelected()
	} else {
		u.startSelected()
	}
}

func (u *ui) startSelected() {
	for _, r := range u.selectedRows() {
		if r.Running {
			continue
		}
		id := r.ID
		u.async(func() error { _, err := u.a.StartLine(id, 0); return err })
	}
}

func (u *ui) stopSelected() {
	for _, r := range u.selectedRows() {
		if r.Running {
			id := r.ID
			u.async(func() error { return u.a.StopLine(id) })
		}
	}
}

func (u *ui) stopSelectedLine() {
	for _, i := range u.linesTV.SelectedIndexes() {
		if i >= 0 && i < len(u.lm.rows) {
			id := u.lm.rows[i].ID
			u.async(func() error { return u.a.StopLine(id) })
		}
	}
}

func (u *ui) copyLineAddr() {
	var addrs []string
	for _, i := range u.linesTV.SelectedIndexes() {
		if i >= 0 && i < len(u.lm.rows) {
			addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", u.lm.rows[i].LocalPort))
		}
	}
	if len(addrs) > 0 {
		_ = walk.Clipboard().SetText(strings.Join(addrs, "\r\n"))
	}
}

func idsOf(rows []app.Row) []string {
	var ids []string
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids
}

func (u *ui) checkSelected() {
	if ids := idsOf(u.selectedRows()); len(ids) > 0 {
		u.act(u.a.CheckIDs(ids))
	}
}

func (u *ui) speedSelected() {
	if ids := idsOf(u.selectedRows()); len(ids) > 0 {
		u.act(u.a.SpeedTest(ids))
	}
}

func (u *ui) speedChecked() {
	ids := u.rm.CheckedIDs()
	if len(ids) == 0 {
		walk.MsgBox(u.mw, "proxycheck", "Отметьте серверы галочками слева.", walk.MsgBoxIconInformation)
		return
	}
	u.act(u.a.SpeedTest(ids))
}

func (u *ui) copySelected() {
	var links []string
	for _, r := range u.selectedRows() {
		if ci, err := u.a.Config(r.ID); err == nil && ci.Link != "" {
			links = append(links, ci.Link)
		}
	}
	if len(links) > 0 {
		_ = walk.Clipboard().SetText(strings.Join(links, "\r\n"))
		u.status.SetText(fmt.Sprintf("Скопировано ссылок: %d", len(links)))
	}
}

func (u *ui) deleteSelected() {
	rows := u.selectedRows()
	if len(rows) == 0 {
		return
	}
	msg := fmt.Sprintf("Удалить из списка выбранные серверы (%d)?", len(rows))
	if len(rows) == 1 {
		msg = "Удалить сервер «" + CellText(rows[0], 2) + "» из списка?"
	}
	if walk.MsgBox(u.mw, "proxycheck", msg, walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	for _, r := range rows {
		u.fail(u.a.Delete(r.ID))
	}
}

func (u *ui) editSelected() {
	rows := u.selectedRows()
	if len(rows) != 1 {
		return
	}
	ci, err := u.a.Config(rows[0].ID)
	if err != nil {
		u.fail(err)
		return
	}
	u.tabs.SetCurrentIndex(1)
	u.manual.edit(ci.Node, rows[0].ID)
}

func (u *ui) configSelected() {
	rows := u.selectedRows()
	if len(rows) != 1 {
		return
	}
	ci, err := u.a.Config(rows[0].ID)
	if err != nil {
		u.fail(err)
		return
	}
	var keys []string
	for k := range ci.Fields {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k + ": " + ci.Fields[k] + "\r\n")
	}
	if ci.Skipped != "" {
		sb.WriteString("\r\nЯдро не сможет использовать этот сервер: " + ci.Skipped + "\r\n")
	}
	var dlg *walk.Dialog
	var link *walk.TextEdit
	if err := (Dialog{
		AssignTo: &dlg, Title: "Конфиг: " + CellText(rows[0], 2), MinSize: Size{Width: 560, Height: 420},
		Layout: VBox{},
		Children: []Widget{
			TextEdit{AssignTo: &link, Text: ci.Link, ReadOnly: true, VScroll: true, MaxSize: Size{Height: 90}},
			TextEdit{Text: sb.String(), ReadOnly: true, VScroll: true},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				PushButton{Text: "Копировать ссылку", OnClicked: func() { _ = walk.Clipboard().SetText(ci.Link) }},
				HSpacer{},
				PushButton{Text: "Закрыть", OnClicked: func() { dlg.Close(0) }},
			}},
		},
	}).Create(u.mw); err != nil {
		u.fail(err)
		return
	}
	dlg.Run()
}
