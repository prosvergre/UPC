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

	all          []app.Row // все строки из ядра приложения
	rows         []app.Row // строки текущей вкладки (то, что показано)
	view         string
	sortCol      int
	sortAsc      bool
	checkedFirst bool // отмеченные всегда сверху
	checked      map[string]bool
	onCheck      func(id string, on bool)
	font         *walk.Font // шрифт таблицы (для кода страны, который рисуется вручную)
}

func newRowModel() *rowModel {
	return &rowModel{checked: map[string]bool{}, sortCol: -1, sortAsc: true, view: app.ViewMain}
}

func (m *rowModel) RowCount() int { return len(m.rows) }

// Колонка 0 модели — только галочка; данные начинаются с колонки 1.
func (m *rowModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.rows) || col < 1 {
		return ""
	}
	if col == 1 {
		return "" // страна рисуется вручную: флаг + код
	}
	return CellText(m.rows[row], col-1)
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
	if col < 1 {
		// клик по заголовку колонки с галочками: отмеченные всегда сверху
		// (первый клик включает, следующий выключает)
		m.checkedFirst = order == walk.SortAscending
		m.SorterBase.Sort(col, order)
		m.resort()
		m.PublishRowsReset()
		return nil
	}
	m.sortCol, m.sortAsc = col-1, order == walk.SortAscending
	m.SorterBase.Sort(col, order)
	m.resort()
	m.PublishRowsReset()
	return nil
}

func (m *rowModel) resort() {
	if m.sortCol >= 0 {
		SortRows(m.rows, m.sortCol, m.sortAsc)
	}
	if m.checkedFirst {
		CheckedFirst(m.rows, func(id string) bool { return m.checked[id] })
	}
}

// SetView переключает вкладку.
func (m *rowModel) SetView(view string) {
	if m.view == view {
		return
	}
	m.view = view
	m.refilter()
	m.PublishRowsReset()
}

func (m *rowModel) refilter() {
	m.rows = m.rows[:0:0]
	for _, r := range m.all {
		if app.MatchView(r, m.view) {
			m.rows = append(m.rows, r)
		}
	}
	m.resort()
}

// Count возвращает число строк вида (для подписей вкладок).
func (m *rowModel) Count(view string) int {
	n := 0
	for _, r := range m.all {
		if app.MatchView(r, view) {
			n++
		}
	}
	return n
}

// Set подставляет новые данные; возвращает true, если таблица изменилась.
func (m *rowModel) Set(rows []app.Row) bool {
	if reflect.DeepEqual(rows, m.all) {
		return false
	}
	m.all = append([]app.Row(nil), rows...)
	for _, r := range m.all {
		if r.Selected {
			if _, known := m.checked[r.ID]; !known {
				m.checked[r.ID] = true
			}
		}
	}
	m.refilter()
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
	for _, r := range m.all {
		if r.Trashed {
			continue
		}
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
	switch s.Col() - 1 {
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
	// флаг 4:3 подгоняется под высоту строки (не больше 24×18 при 96 DPI)
	h := b.Height - 2*dpi/96
	if max := 18 * dpi / 96; h > max {
		h = max
	}
	if h < 8 {
		return
	}
	w := h * 4 / 3
	y := b.Y + (b.Height-h)/2
	gap := 4 * dpi / 96
	_ = canvas.DrawImageStretchedPixels(bmp, walk.Rectangle{X: b.X + gap, Y: y, Width: w, Height: h})
	if m.font != nil {
		_ = canvas.DrawTextPixels(code, m.font, walk.RGB(0, 0, 0),
			walk.Rectangle{X: b.X + gap + w + gap, Y: b.Y, Width: b.Width - (2*gap + w), Height: b.Height},
			walk.TextLeft|walk.TextVCenter|walk.TextSingleLine|walk.TextNoPrefix)
	}
}
