//go:build windows

package winui

import (
	"fmt"
	"strings"

	"github.com/tailscale/walk"
	. "github.com/tailscale/walk/declarative"

	"proxycheck/internal/node"
)

type optItem struct{ Value, Label string }

type fieldCtl struct {
	get func() string
	set func(string)
}

type manualUI struct {
	u       *ui
	proto   *walk.ComboBox
	host    *walk.Composite
	ctls    map[string]*fieldCtl
	editID  string
	addBtn  *walk.PushButton
	addChk  *walk.PushButton
	cancel  *walk.PushButton
	result  *walk.Label
	impText *walk.TextEdit
	impChk  *walk.CheckBox
	impRes  *walk.Label
	protos  []*optItem
}

func (u *ui) manualPage() []Widget {
	m := &u.manual
	return []Widget{
		Composite{
			Layout: HBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}, Spacing: 16},
			Children: []Widget{
				Composite{
					Layout: VBox{MarginsZero: true}, MinSize: Size{Width: 520},
					Children: []Widget{
						Label{Text: "Ввод параметров", Font: Font{Bold: true}},
						Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
							Label{Text: "Протокол", MinSize: Size{Width: 150}},
							ComboBox{AssignTo: &m.proto, MinSize: Size{Width: 220}},
							HSpacer{},
						}},
						ScrollView{
							Layout: VBox{MarginsZero: true},
							Children: []Widget{
								Composite{AssignTo: &m.host, Layout: Grid{Columns: 2, MarginsZero: true, Spacing: 6}},
							},
						},
						Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
							PushButton{AssignTo: &m.addBtn, Text: "Добавить", OnClicked: func() { m.submit(false) }},
							PushButton{AssignTo: &m.addChk, Text: "Добавить и проверить", OnClicked: func() { m.submit(true) }},
							PushButton{AssignTo: &m.cancel, Text: "Отменить правку", Visible: false, OnClicked: m.cancelEdit},
							HSpacer{},
						}},
						Label{AssignTo: &m.result, Text: ""},
					},
				},
				Composite{
					Layout: VBox{MarginsZero: true},
					Children: []Widget{
						Label{Text: "Вставка из буфера обмена", Font: Font{Bold: true}},
						Label{Text: "ss://  vless://  vmess://  trojan://  socks5://  http://  hysteria2://  tuic://  wireguard://  ssh://\r\nпо одной в строке, либо подписка целиком."},
						TextEdit{AssignTo: &m.impText, VScroll: true, MinSize: Size{Height: 160}},
						CheckBox{AssignTo: &m.impChk, Text: "сразу проверить добавленные", Checked: true},
						Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
							PushButton{Text: "Вставить из буфера", OnClicked: m.paste},
							PushButton{Text: "Добавить", OnClicked: m.importText},
							HSpacer{},
						}},
						Label{AssignTo: &m.impRes, Text: ""},
					},
				},
			},
		},
	}
}

func (m *manualUI) init(u *ui) {
	m.u = u
	for _, p := range Protocols {
		m.protos = append(m.protos, &optItem{p.ID, p.Name})
	}
	_ = m.proto.SetBindingMember("Value")
	_ = m.proto.SetDisplayMember("Label")
	_ = m.proto.SetModel(m.protos)
	m.proto.SetCurrentIndex(0)
	m.proto.CurrentIndexChanged().Attach(func() { m.rebuild(m.currentProto(), nil) })
	m.rebuild(m.currentProto(), nil)
}

func (m *manualUI) currentProto() string {
	if i := m.proto.CurrentIndex(); i >= 0 && i < len(m.protos) {
		return m.protos[i].Value
	}
	return node.SS
}

// rebuild пересоздаёт поля формы под протокол; vals — начальные значения.
func (m *manualUI) rebuild(proto string, vals map[string]string) {
	info, ok := ProtoByID(proto)
	if !ok {
		return
	}
	ch := m.host.Children()
	for i := ch.Len() - 1; i >= 0; i-- {
		ch.At(i).Dispose()
	}
	m.ctls = map[string]*fieldCtl{}
	all := append(append([]Field(nil), CommonFields...), info.Fields...)
	for _, f := range all {
		lb, _ := walk.NewLabel(m.host)
		_ = lb.SetText(f.Label)
		lb.SetMinMaxSize(walk.Size{Width: 190}, walk.Size{})
		m.ctls[f.Key] = m.newControl(f)
	}
	if vals != nil {
		for k, v := range vals {
			if c := m.ctls[k]; c != nil {
				c.set(v)
			}
		}
	}
	m.host.RequestLayout()
}

func (m *manualUI) newControl(f Field) *fieldCtl {
	switch f.Kind {
	case Select:
		cb, _ := walk.NewComboBox(m.host)
		items := make([]*optItem, len(f.Opts))
		for i, o := range f.Opts {
			items[i] = &optItem{o.Value, o.Label}
		}
		_ = cb.SetBindingMember("Value")
		_ = cb.SetDisplayMember("Label")
		_ = cb.SetModel(items)
		cb.SetMinMaxSize(walk.Size{Width: 260}, walk.Size{})
		cb.SetCurrentIndex(0)
		return &fieldCtl{
			get: func() string {
				if i := cb.CurrentIndex(); i >= 0 && i < len(items) {
					return items[i].Value
				}
				return ""
			},
			set: func(v string) {
				for i, it := range items {
					if it.Value == v {
						cb.SetCurrentIndex(i)
						return
					}
				}
			},
		}
	case Check:
		ck, _ := walk.NewCheckBox(m.host)
		return &fieldCtl{
			get: func() string {
				if ck.Checked() {
					return "1"
				}
				return ""
			},
			set: func(v string) { ck.SetChecked(v == "1" || v == "true") },
		}
	case Area:
		te, _ := walk.NewTextEdit(m.host)
		te.SetMinMaxSize(walk.Size{Width: 260, Height: 70}, walk.Size{})
		return &fieldCtl{get: te.Text, set: func(v string) { _ = te.SetText(strings.ReplaceAll(v, "\n", "\r\n")) }}
	default:
		le, _ := walk.NewLineEdit(m.host)
		le.SetMinMaxSize(walk.Size{Width: 260}, walk.Size{})
		if f.Kind == Password {
			// пароль показываем открытым: это прокси-учётки, их нужно видеть и сверять
		}
		return &fieldCtl{get: le.Text, set: func(v string) { _ = le.SetText(v) }}
	}
}

func (m *manualUI) values() map[string]string {
	v := map[string]string{}
	for k, c := range m.ctls {
		v[k] = c.get()
	}
	return v
}

func (m *manualUI) submit(check bool) {
	n, err := BuildNode(m.currentProto(), m.values())
	if err != nil {
		m.result.SetText("Ошибка: " + err.Error())
		return
	}
	id, err := m.u.a.AddManual(n, m.editID)
	if err != nil {
		m.result.SetText("Ошибка: " + err.Error())
		return
	}
	msg := "Добавлено"
	if m.editID != "" {
		msg = "Сохранено"
	}
	m.setEdit("")
	if check {
		if err := m.u.a.CheckIDs([]string{id}); err != nil {
			msg += ", но проверка не запущена: " + err.Error()
		}
	}
	m.result.SetText(msg)
}

func (m *manualUI) setEdit(id string) {
	m.editID = id
	if id != "" {
		m.addBtn.SetText("Сохранить")
		m.addChk.SetText("Сохранить и проверить")
	} else {
		m.addBtn.SetText("Добавить")
		m.addChk.SetText("Добавить и проверить")
	}
	m.cancel.SetVisible(id != "")
}

// edit заполняет форму существующим сервером.
func (m *manualUI) edit(n node.Node, id string) {
	for i, p := range m.protos {
		if p.Value == n.Proto {
			m.proto.SetCurrentIndex(i)
		}
	}
	m.rebuild(n.Proto, ValuesFromNode(n))
	m.setEdit(id)
	m.result.SetText("Редактирование. UoT, мультиплексирование и JSON не входят в ссылку и при её копировании не передаются.")
}

func (m *manualUI) cancelEdit() {
	m.setEdit("")
	m.rebuild(m.currentProto(), nil)
	m.result.SetText("")
}

func (m *manualUI) paste() {
	text, err := walk.Clipboard().Text()
	if err != nil || strings.TrimSpace(text) == "" {
		m.impRes.SetText("В буфере обмена нет текста.")
		return
	}
	_ = m.impText.SetText(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n"))
}

func (m *manualUI) importText() {
	text := strings.ReplaceAll(m.impText.Text(), "\r\n", "\n")
	if strings.TrimSpace(text) == "" {
		m.impRes.SetText("Вставьте ссылки в поле выше.")
		return
	}
	res := m.u.a.Import(text)
	msg := fmt.Sprintf("Добавлено: %d, уже было: %d, отклонено: %d", res.Added, res.Existing, res.Rejected)
	if len(res.Rejections) > 0 {
		msg += "\r\n" + strings.Join(res.Rejections, "\r\n")
	}
	if m.impChk.Checked() && len(res.IDs) > 0 {
		if err := m.u.a.CheckIDs(res.IDs); err != nil {
			msg += "\r\nПроверка не запущена: " + err.Error()
		}
	}
	m.impRes.SetText(msg)
}
