//go:build windows

package winui

import (
	"fmt"
	"strings"
	"time"

	"github.com/tailscale/walk"
	. "github.com/tailscale/walk/declarative"

	"proxycheck/internal/firewall"
	"proxycheck/internal/settings"
)

type subModel struct {
	walk.TableModelBase
	rows []settings.Subscription
}

func (m *subModel) RowCount() int { return len(m.rows) }

func fmtUnix(u int64) string {
	if u == 0 {
		return "—"
	}
	return time.Unix(u, 0).Format("02.01.2006 15:04")
}

func subState(s settings.Subscription) string {
	switch {
	case s.LastError != "":
		return "ошибка: " + s.LastError
	case s.Stale:
		return "устарел — не загружается"
	case !s.Enabled:
		return "выключен"
	case s.LastFetch != 0:
		return "ок"
	}
	return "не загружался"
}

func (m *subModel) Value(row, col int) interface{} {
	s := m.rows[row]
	switch col {
	case 0:
		return s.Name
	case 1:
		return s.URL
	case 2:
		if s.MaxAgeDays == 0 {
			return "—"
		}
		return fmt.Sprint(s.MaxAgeDays)
	case 3:
		return fmtUnix(s.RemoteUpdated)
	case 4:
		return fmtUnix(s.LastFetch)
	case 5:
		return fmt.Sprint(s.Count)
	case 6:
		return fmt.Sprint(s.Alive)
	case 7:
		return subState(s)
	}
	return ""
}

func (m *subModel) Checked(row int) bool { return m.rows[row].Enabled }
func (m *subModel) SetChecked(row int, on bool) error {
	m.rows[row].Enabled = on
	return nil
}

type settingsUI struct {
	u     *ui
	tv    *walk.TableView
	model *subModel
	name  *walk.LineEdit
	url   *walk.LineEdit
	age   *walk.NumberEdit
	res   *walk.Label

	autoMin   *walk.NumberEdit
	autoStart *walk.CheckBox
	lan       *walk.CheckBox
	autoRes   *walk.Label
	info      *walk.Label
	dirty     bool
}

func (u *ui) settingsPage() []Widget {
	s := &u.settings
	s.model = &subModel{}
	return []Widget{
		Composite{
			Layout: VBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}},
			Children: []Widget{
				Label{Text: "Источники (подписки)", Font: Font{Bold: true}},
				TableView{
					AssignTo: &s.tv, Model: s.model, CheckBoxes: true, AlternatingRowBG: true, MinSize: Size{Height: 170},
					Columns: []TableViewColumn{
						{Title: "Название", Width: 150}, {Title: "Ссылка", Width: 330}, {Title: "Макс. возраст, дн.", Width: 110},
						{Title: "Обновлён на сервере", Width: 130}, {Title: "Загружено у нас", Width: 120},
						{Title: "Скачано", Width: 65, Alignment: AlignFar}, {Title: "Живых", Width: 60, Alignment: AlignFar}, {Title: "Состояние", Width: 200},
					},
					OnCurrentIndexChanged: s.rowSelected,
				},
				Composite{Layout: Grid{Columns: 4, MarginsZero: true, Spacing: 6}, Children: []Widget{
					Label{Text: "Название"}, LineEdit{AssignTo: &s.name},
					Label{Text: "Макс. возраст, дн. (0 — не проверять)"}, NumberEdit{AssignTo: &s.age, MinValue: 0, MaxValue: 3650, Decimals: 0},
					Label{Text: "Ссылка"}, LineEdit{AssignTo: &s.url, ColumnSpan: 3},
				}},
				Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
					PushButton{Text: "Добавить", OnClicked: s.add},
					PushButton{Text: "Применить к строке", OnClicked: s.apply},
					PushButton{Text: "Удалить", OnClicked: s.remove},
					PushButton{Text: "Сохранить всё", OnClicked: s.save},
					PushButton{Text: "Обновить даты", OnClicked: s.refreshDates},
					HSpacer{},
				}},
				Label{AssignTo: &s.res, Text: ""},
				Label{Text: "Если источник не обновлялся на удалённой стороне дольше «макс. возраста», он не загружается, пока там не появится обновление. Дата проверяется при каждой проверке."},

				Label{Text: "Автозагрузка и сеть", Font: Font{Bold: true}},
				Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
					Label{Text: "Проверять каждые, мин (0 — выключено):"},
					NumberEdit{AssignTo: &s.autoMin, MinValue: 0, MaxValue: 10080, Decimals: 0, MaxSize: Size{Width: 80}},
					CheckBox{AssignTo: &s.autoStart, Text: "при запуске программы загрузить и проверить сразу"},
					HSpacer{},
				}},
				CheckBox{AssignTo: &s.lan, Text: "Разрешить подключения к линиям из локальной сети (иначе только с этого компьютера)"},
				Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
					PushButton{Text: "Сохранить", OnClicked: s.saveAuto},
					PushButton{Text: "Открыть порты линий в брандмауэре (нужны права администратора)", OnClicked: s.openFirewall},
					HSpacer{},
				}},
				Label{AssignTo: &s.autoRes, Text: ""},
				Label{AssignTo: &s.info, Text: ""},
			},
		},
	}
}

func (s *settingsUI) init(u *ui) {
	s.u = u
	s.reload()
	au := u.a.Auto()
	_ = s.autoMin.SetValue(float64(au.ScanMin))
	s.autoStart.SetChecked(au.ScanOnStart)
	s.lan.SetChecked(u.a.LinesLAN())
	s.info.SetText("Веб-интерфейс запускается параметром -web (адрес -web-addr, пароль -set-web-password).")
}

// reload перечитывает подписки, если пользователь не правит их прямо сейчас.
func (s *settingsUI) reload() {
	if s.dirty {
		return
	}
	idx := s.tv.CurrentIndex()
	s.model.rows = s.u.a.Subscriptions()
	s.model.PublishRowsReset()
	if idx >= 0 && idx < len(s.model.rows) {
		_ = s.tv.SetCurrentIndex(idx)
	}
}

func (s *settingsUI) rowSelected() {
	i := s.tv.CurrentIndex()
	if i < 0 || i >= len(s.model.rows) {
		return
	}
	r := s.model.rows[i]
	_ = s.name.SetText(r.Name)
	_ = s.url.SetText(r.URL)
	_ = s.age.SetValue(float64(r.MaxAgeDays))
}

func (s *settingsUI) add() {
	s.model.rows = append(s.model.rows, settings.Subscription{Enabled: true, Name: "Новый источник"})
	s.model.PublishRowsReset()
	s.dirty = true
	_ = s.tv.SetCurrentIndex(len(s.model.rows) - 1)
	s.rowSelected()
	_ = s.url.SetFocus()
}

func (s *settingsUI) apply() {
	i := s.tv.CurrentIndex()
	if i < 0 || i >= len(s.model.rows) {
		return
	}
	s.model.rows[i].Name = strings.TrimSpace(s.name.Text())
	s.model.rows[i].URL = strings.TrimSpace(s.url.Text())
	s.model.rows[i].MaxAgeDays = int(s.age.Value())
	s.model.PublishRowChanged(i)
	s.dirty = true
}

func (s *settingsUI) remove() {
	i := s.tv.CurrentIndex()
	if i < 0 || i >= len(s.model.rows) {
		return
	}
	s.model.rows = append(s.model.rows[:i], s.model.rows[i+1:]...)
	s.model.PublishRowsReset()
	s.dirty = true
}

func (s *settingsUI) save() {
	s.apply()
	if err := s.u.a.SetSubscriptions(s.model.rows); err != nil {
		s.res.SetText("Ошибка: " + err.Error())
		return
	}
	s.dirty = false
	s.reload()
	s.res.SetText("Сохранено")
}

func (s *settingsUI) refreshDates() {
	s.save()
	if s.dirty {
		return
	}
	if err := s.u.a.RefreshSubs(); err != nil {
		s.res.SetText("Ошибка: " + err.Error())
		return
	}
	s.res.SetText("Проверяю даты обновления…")
}

func (s *settingsUI) saveAuto() {
	err := s.u.a.SetAuto(appAuto(int(s.autoMin.Value()), s.autoStart.Checked()))
	if err == nil {
		err = s.u.a.SetLinesLAN(s.lan.Checked())
	}
	if err != nil {
		s.autoRes.SetText("Ошибка: " + err.Error())
		return
	}
	s.autoRes.SetText("Сохранено")
}

func (s *settingsUI) openFirewall() {
	start := s.u.a.Settings().StartPort
	if start <= 0 {
		start = 1080
	}
	if err := firewall.EnsureInboundRule("proxycheck (SOCKS5)", start, start+99); err != nil {
		s.autoRes.SetText("Не удалось: " + err.Error() + " (запустите программу от имени администратора)")
		return
	}
	s.autoRes.SetText(fmt.Sprintf("Правило брандмауэра создано для портов %d–%d.", start, start+99))
}
