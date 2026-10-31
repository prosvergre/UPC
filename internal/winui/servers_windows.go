//go:build windows

package winui

import (
	"reflect"
	"sort"

	"github.com/tailscale/walk"

	"proxycheck/internal/app"
)

// rowModel — модель таблицы серверов (с сортировкой, отметками и раскраской).
type rowModel struct {
	walk.TableModelBase
	walk.SorterBase

	rows    []app.Row
	sortCol int
	sortAsc bool
	checked map[string]bool
	onCheck func(id string, on bool)
}

func newRowModel() *rowModel {
	return &rowModel{checked: map[string]bool{}, sortCol: -1, sortAsc: true}
}

func (m *rowModel) RowCount() int { return len(m.rows) }

func (m *rowModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.rows) {
		return ""
	}
	return CellText(m.rows[row], col)
}

// Checked/SetChecked — галочки отметки серверов (для замера скорости).
func (m *rowModel) Checked(row int) bool { return m.checked[m.rows[row].ID] }
func (m *rowModel) SetChecked(row int, on bool) error {
	id := m.rows[row].ID
	m.checked[id] = on
	if m.onCheck != nil {
		m.onCheck(id, on)
	}
	return nil
}

func (m *rowModel) Sort(col int, order walk.SortOrder) error {
	m.sortCol, m.sortAsc = col, order == walk.SortAscending
	m.SorterBase.Sort(col, order)
	m.resort()
	m.PublishRowsReset()
	return nil
}

func (m *rowModel) resort() {
	if m.sortCol >= 0 {
		SortRows(m.rows, m.sortCol, m.sortAsc)
	}
}

// Set подставляет новые данные; возвращает true, если таблица изменилась.
func (m *rowModel) Set(rows []app.Row) bool {
	if reflect.DeepEqual(rows, m.rows) {
		return false
	}
	m.rows = append([]app.Row(nil), rows...)
	for _, r := range m.rows {
		if r.Selected {
			if _, known := m.checked[r.ID]; !known {
				m.checked[r.ID] = true
			}
		}
	}
	m.resort()
	m.PublishRowsReset()
	return true
}

func (m *rowModel) IDs(rows []int) []string {
	var ids []string
	for _, i := range rows {
		if i >= 0 && i < len(m.rows) {
			ids = append(ids, m.rows[i].ID)
		}
	}
	return ids
}

func (m *rowModel) CheckedIDs() []string {
	var ids []string
	for _, r := range m.rows {
		if m.checked[r.ID] {
			ids = append(ids, r.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func (m *rowModel) IndexOf(id string) int {
	for i, r := range m.rows {
		if r.ID == id {
			return i
		}
	}
	return -1
}

var (
	colAlive = walk.RGB(0x1a, 0x7f, 0x37)
	colDead  = walk.RGB(0xc0, 0x39, 0x2b)
	colDied  = walk.RGB(0xb9, 0x77, 0x0e)
	colMuted = walk.RGB(0x70, 0x70, 0x70)
)

// StyleCell раскрашивает статус и рисует прямоугольный флаг в колонке страны.
func (m *rowModel) StyleCell(s *walk.CellStyle) {
	row := s.Row()
	if row < 0 || row >= len(m.rows) {
		return
	}
	r := m.rows[row]
	switch s.Col() {
	case 0:
		if r.Country != "" {
			m.drawFlag(s, r.Country)
		}
	case 1:
		switch r.Status {
		case app.StatusAlive:
			s.TextColor = colAlive
		case app.StatusDead:
			s.TextColor = colDead
		case app.StatusDied:
			s.TextColor = colDied
		default:
			s.TextColor = colMuted
		}
	case 4:
		s.TextColor = colMuted
	case 7:
		if r.ExitIP == "" && r.ExitErr != "" {
			s.TextColor = colMuted
		}
	case 8:
		if r.SpeedErr != "" && r.SpeedMbps == 0 {
			s.TextColor = colDead
		}
	}
}

func (m *rowModel) drawFlag(s *walk.CellStyle, code string) {
	canvas := s.Canvas()
	if canvas == nil {
		return
	}
	dpi := canvas.DPI()
	bmp := flagBitmap(code, dpi)
	if bmp == nil {
		return
	}
	b := s.BoundsPixels()
	w, h := 24*dpi/96, 18*dpi/96
	y := b.Y + (b.Height-h)/2
	_ = canvas.DrawImageStretchedPixels(bmp, walk.Rectangle{X: b.X + 4*dpi/96, Y: y, Width: w, Height: h})
}
