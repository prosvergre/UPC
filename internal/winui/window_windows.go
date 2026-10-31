//go:build windows

package winui

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/tailscale/walk"
	. "github.com/tailscale/walk/declarative"
	"github.com/tailscale/win"

	"proxycheck/internal/app"
)

// Options — параметры запуска окна.
type Options struct {
	StartMinimized bool
}

type ui struct {
	a    *app.App
	opts Options
	mw   *walk.MainWindow
	done chan struct{}

	tabs                                     *walk.TabWidget
	tv                                       *walk.TableView
	rm                                       *rowModel
	linesTV                                  *walk.TableView
	lm                                       *lineModel
	status                                   *walk.Label
	detail                                   *walk.Label
	prog                                     *walk.ProgressBar
	scanBtn, recheckBtn, speedBtn, cancelBtn *walk.PushButton
	logEdit                                  *walk.TextEdit
	ni                                       *walk.NotifyIcon

	quitting bool
	busy     bool
	prevBusy bool
	lines    []app.Line
	lastLog  int

	manual   manualUI
	settings settingsUI
	ctxActs  struct{ start, stop *walk.Action }
}

// lineModel — таблица активных линий.
type lineModel struct {
	walk.TableModelBase
	rows []app.Line
}

func (m *lineModel) RowCount() int { return len(m.rows) }
func (m *lineModel) Value(row, col int) interface{} {
	l := m.rows[row]
	switch col {
	case 0:
		return fmt.Sprint(l.LocalPort)
	case 1:
		return l.Name
	case 2:
		if l.Alive {
			return "работает"
		}
		return "не отвечает"
	}
	return ""
}

// Run открывает окно и блокируется до его закрытия. Возвращает код выхода.
func Run(a *app.App, opts Options) int {
	u := &ui{a: a, opts: opts, rm: newRowModel(), lm: &lineModel{}, done: make(chan struct{})}
	u.rm.onCheck = func(id string, on bool) { a.Select(id, on) }

	cols := []TableViewColumn{}
	for _, c := range ServerCols {
		al := AlignDefault
		if c.Right {
			al = AlignFar
		}
		cols = append(cols, TableViewColumn{Title: c.Title, Width: c.Width, Alignment: al})
	}

	err := MainWindow{
		AssignTo: &u.mw,
		Title:    "proxycheck",
		MinSize:  Size{Width: 900, Height: 560},
		Size:     Size{Width: 1180, Height: 720},
		Layout:   VBox{MarginsZero: true, SpacingZero: true},
		Children: []Widget{
			Composite{
				Layout: HBox{Margins: Margins{Left: 8, Top: 6, Right: 8, Bottom: 6}},
				Children: []Widget{
					PushButton{AssignTo: &u.scanBtn, Text: "Загрузить и проверить", OnClicked: func() { u.act(a.Scan()) }},
					PushButton{AssignTo: &u.recheckBtn, Text: "Перепроверить", OnClicked: func() { u.act(a.Recheck()) }},
					PushButton{AssignTo: &u.speedBtn, Text: "Скорость отмеченных", OnClicked: u.speedChecked},
					PushButton{AssignTo: &u.cancelBtn, Text: "Отмена", Enabled: false, OnClicked: func() { a.Cancel() }},
					HSpacer{},
				},
			},
			TabWidget{
				AssignTo: &u.tabs,
				Pages: []TabPage{
					{Title: "Серверы", Layout: VBox{Margins: Margins{Left: 6, Top: 6, Right: 6, Bottom: 6}}, Children: []Widget{
						GroupBox{Title: "Активные линии", Layout: VBox{Margins: Margins{Left: 4, Top: 2, Right: 4, Bottom: 4}}, MaxSize: Size{Height: 120}, Children: []Widget{
							TableView{
								AssignTo: &u.linesTV, Model: u.lm, MinSize: Size{Height: 60},
								Columns: []TableViewColumn{{Title: "Порт", Width: 70}, {Title: "Сервер", Width: 420}, {Title: "Статус", Width: 110}},
								ContextMenuItems: []MenuItem{
									Action{Text: "Остановить линию", OnTriggered: u.stopSelectedLine},
									Action{Text: "Копировать адрес прокси", OnTriggered: u.copyLineAddr},
								},
							},
						}},
						TableView{
							AssignTo: &u.tv, Model: u.rm, Columns: cols,
							CheckBoxes: true, MultiSelection: true, AlternatingRowBG: true, ColumnsOrderable: false,
							StyleCell:       u.rm.StyleCell,
							OnItemActivated: u.startOrStop,
							ContextMenuItems: []MenuItem{
								Action{AssignTo: &u.ctxActs.start, Text: "Запустить линию", OnTriggered: u.startSelected},
								Action{AssignTo: &u.ctxActs.stop, Text: "Остановить линию", OnTriggered: u.stopSelected},
								Action{Text: "Проверить", OnTriggered: u.checkSelected},
								Action{Text: "Замерить скорость", OnTriggered: u.speedSelected},
								Separator{},
								Action{Text: "Редактировать…", OnTriggered: u.editSelected},
								Action{Text: "Конфиг…", OnTriggered: u.configSelected},
								Action{Text: "Копировать ссылку", OnTriggered: u.copySelected},
								Separator{},
								Action{Text: "Удалить из списка", OnTriggered: u.deleteSelected},
							},
							OnSelectedIndexesChanged: u.selectionChanged,
						},
					}},
					{Title: "Вручную", Layout: VBox{}, Children: u.manualPage()},
					{Title: "Настройки", Layout: VBox{}, Children: u.settingsPage()},
					{Title: "Журнал", Layout: VBox{Margins: Margins{Left: 6, Top: 6, Right: 6, Bottom: 6}}, Children: []Widget{
						TextEdit{AssignTo: &u.logEdit, ReadOnly: true, VScroll: true, Font: Font{Family: "Consolas", PointSize: 9}},
					}},
				},
			},
			Composite{
				Layout: HBox{Margins: Margins{Left: 8, Top: 4, Right: 8, Bottom: 6}},
				Children: []Widget{
					Label{AssignTo: &u.status, Text: "Простаивает", MinSize: Size{Width: 380}},
					ProgressBar{AssignTo: &u.prog, MinValue: 0, MaxValue: 100, MaxSize: Size{Width: 220}},
					Label{AssignTo: &u.detail, Text: ""},
				},
			},
		},
	}.Create()
	if err != nil {
		walk.MsgBox(nil, "proxycheck", "Не удалось создать окно: "+err.Error(), walk.MsgBoxIconError)
		return 1
	}
	u.setupTray()
	u.afterCreate()
	u.mw.Closing().Attach(u.onClosing)

	go u.poll()
	if opts.StartMinimized {
		u.mw.SetVisible(false)
	} else {
		u.mw.Show()
	}
	rc := walk.App().Run()
	close(u.done)
	return rc
}

func (u *ui) fail(err error) {
	if err != nil {
		walk.MsgBox(u.mw, "proxycheck", err.Error(), walk.MsgBoxIconError)
	}
}

// act показывает ошибку запуска задачи (например, «приложение занято»).
func (u *ui) act(err error) { u.fail(err) }

// poll опрашивает ядро приложения и обновляет окно: чаще при работе, реже в простое.
func (u *ui) poll() {
	for {
		snap := u.a.Snapshot()
		u.mw.Synchronize(func() { u.apply(snap) })
		d := 2 * time.Second
		if snap.Activity.State != app.Idle {
			d = 600 * time.Millisecond
		}
		select {
		case <-time.After(d):
		case <-u.done:
			return
		}
	}
}

func (u *ui) apply(s app.Snapshot) {
	u.busy = s.Activity.State != app.Idle
	text := ActivityText(s.Activity)
	if !s.CoreOK {
		text += " — ядро sing-box не найдено: " + s.Core
	}
	u.status.SetText(text)
	switch p := Percent(s.Activity); {
	case p < 0:
		u.prog.SetMarqueeMode(true)
	default:
		u.prog.SetMarqueeMode(false)
		u.prog.SetValue(p)
	}
	u.scanBtn.SetEnabled(!u.busy)
	u.recheckBtn.SetEnabled(!u.busy)
	u.speedBtn.SetEnabled(!u.busy)
	u.cancelBtn.SetEnabled(u.busy)

	// выделение сохраняем по ID, чтобы оно не прыгало при обновлении таблицы
	keep := u.rm.IDs(u.tv.SelectedIndexes())
	if u.rm.Set(s.Rows) && len(keep) > 0 {
		var idx []int
		for _, id := range keep {
			if i := u.rm.IndexOf(id); i >= 0 {
				idx = append(idx, i)
			}
		}
		_ = u.tv.SetSelectedIndexes(idx)
	}
	if !reflect.DeepEqual(s.Lines, u.lm.rows) {
		u.lm.rows = s.Lines
		u.lm.PublishRowsReset()
	}
	u.lines = s.Lines
	u.showDetail()
	if t := fmt.Sprintf("proxycheck — %d живых из %d, линий: %d", countAlive(s.Rows), len(s.Rows), len(s.Lines)); u.mw.Title() != t {
		_ = u.mw.SetTitle(t)
	}
	if len(s.Log) != u.lastLog {
		u.lastLog = len(s.Log)
		u.logEdit.SetText(strings.Join(s.Log, "\r\n"))
		u.logEdit.SetTextSelection(len(u.logEdit.Text()), len(u.logEdit.Text()))
		u.logEdit.ScrollToCaret()
	}
	if u.prevBusy && !u.busy {
		u.settings.reload()
	}
	u.prevBusy = u.busy
}

func countAlive(rows []app.Row) int {
	n := 0
	for _, r := range rows {
		if r.Status == app.StatusAlive {
			n++
		}
	}
	return n
}

func (u *ui) afterCreate() {
	u.selectionChanged()
	u.manual.init(u)
	u.settings.init(u)
}

func (u *ui) onClosing(canceled *bool, reason walk.CloseReason) {
	if u.quitting {
		return
	}
	if len(u.lines) > 0 {
		// линии работают — окно прячем в трей, чтобы прокси не пропадали
		*canceled = true
		u.mw.SetVisible(false)
		if u.ni != nil {
			_ = u.ni.ShowInfo("proxycheck", "Работает в трее. Правый клик по значку — выход.")
		}
		return
	}
	u.quit()
}

func (u *ui) quit() {
	u.quitting = true
	u.a.Shutdown()
	if u.ni != nil {
		u.ni.Dispose()
	}
	walk.App().Exit(0)
}

func (u *ui) setupTray() {
	ni, err := walk.NewNotifyIcon()
	if err != nil {
		return
	}
	u.ni = ni
	if ic, err := walk.NewIconFromResourceId(1); err == nil {
		_ = ni.SetIcon(ic)
		_ = u.mw.SetIcon(ic)
	}
	_ = ni.SetToolTip("proxycheck")
	show := func() {
		u.mw.Show()
		win.ShowWindow(u.mw.Handle(), win.SW_RESTORE)
		win.SetForegroundWindow(u.mw.Handle())
	}
	open := walk.NewAction()
	_ = open.SetText("Открыть")
	open.Triggered().Attach(show)
	exit := walk.NewAction()
	_ = exit.SetText("Выход")
	exit.Triggered().Attach(u.quit)
	_ = ni.ContextMenu().Actions().Add(open)
	_ = ni.ContextMenu().Actions().Add(exit)
	ni.MouseDown().Attach(func(x, y int, b walk.MouseButton) {
		if b == walk.LeftButton {
			show()
		}
	})
	_ = ni.SetVisible(true)
}

// showDetail показывает причину ошибки для выделенной строки (то, что в вебе —
// подсказка «ⓘ»): почему не определился выходной IP или не прошёл замер скорости.
func (u *ui) showDetail() {
	rows := u.selectedRows()
	text := ""
	if len(rows) == 1 {
		r := rows[0]
		if t := CellTip(r, 7); t != "" {
			text = "Выходной IP не определён: " + t
		} else if t := CellTip(r, 8); t != "" && r.SpeedMbps == 0 {
			text = "Замер скорости: " + t
		}
	}
	if u.detail.Text() != text {
		_ = u.detail.SetText(text)
	}
}
