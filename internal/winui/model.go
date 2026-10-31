package winui

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"proxycheck/internal/app"
)

// Колонки таблицы серверов. Колонка 0 — страна (флаг рисуется вручную, текст —
// двухбуквенный код со сдвигом вправо под флаг); галочка отметки — системная.
var ServerCols = []struct {
	Title string
	Width int
	Right bool
}{
	{"Страна", 70, false}, {"Статус", 70, false}, {"Имя", 230, false}, {"Протокол", 75, false},
	{"Параметры", 150, false}, {"Адрес", 170, false}, {"Задержка", 75, true},
	{"Выходной IP", 130, false}, {"↓ Мбит/с", 75, true}, {"↑ Мбит/с", 75, true},
}

// FlagPad — отступ текста под флаг (флаг 24 px + зазор; пробелы масштабируются
// вместе со шрифтом, так что при любом DPI код не наезжает на флаг).
const FlagPad = "       "

var flagEmoji = regexp.MustCompile("[\U0001F1E6-\U0001F1FF]{2}\\s*")

// StatusText — подпись статуса.
func StatusText(s string) string {
	switch s {
	case app.StatusAlive:
		return "жив"
	case app.StatusDead:
		return "мёртв"
	case app.StatusDied:
		return "умер"
	}
	return "—"
}

// CellText возвращает текст ячейки.
func CellText(r app.Row, col int) string {
	switch col {
	case 0:
		if r.Country == "" {
			return ""
		}
		return FlagPad + r.Country
	case 1:
		return StatusText(r.Status)
	case 2:
		name := flagEmoji.ReplaceAllString(r.Name, "")
		if r.Pinned {
			name += " 📌"
		}
		return name
	case 3:
		return r.Proto
	case 4:
		return r.Summary
	case 5:
		return fmt.Sprintf("%s:%d", r.Host, r.Port)
	case 6:
		if r.Status == app.StatusAlive {
			return fmt.Sprintf("%d мс", r.LatencyMs)
		}
	case 7:
		if r.ExitIP != "" {
			return r.ExitIP
		}
		if r.Status == app.StatusAlive && r.ExitErr != "" {
			return "не определён"
		}
	case 8:
		if r.SpeedMbps > 0 {
			return fmt.Sprintf("%.1f", r.SpeedMbps)
		}
		if r.SpeedErr != "" {
			return "ошибка"
		}
	case 9:
		if r.UlMbps > 0 {
			return fmt.Sprintf("%.1f", r.UlMbps)
		}
	}
	return ""
}

// CellTip — подсказка с причиной ошибки для ячейки (или пусто).
func CellTip(r app.Row, col int) string {
	switch col {
	case 7:
		if r.ExitIP == "" && r.Status == app.StatusAlive {
			return r.ExitErr
		}
	case 8:
		return r.SpeedErr
	}
	return ""
}

func rank(r app.Row, col int) float64 {
	switch col {
	case 6:
		if r.Status != app.StatusAlive {
			return 1e12
		}
		return float64(r.LatencyMs)
	case 8:
		return -r.SpeedMbps
	case 9:
		return -r.UlMbps
	}
	return 0
}

// SortRows сортирует строки по колонке. Числовые колонки — по числу.
func SortRows(rows []app.Row, col int, asc bool) {
	numeric := col == 6 || col == 8 || col == 9
	sort.SliceStable(rows, func(i, j int) bool {
		var less bool
		if numeric {
			a, b := rank(rows[i], col), rank(rows[j], col)
			if a == b {
				return false
			}
			less = a < b
		} else {
			a := strings.ToLower(CellText(rows[i], col))
			b := strings.ToLower(CellText(rows[j], col))
			if a == b {
				return false
			}
			less = a < b
		}
		return less == asc
	})
}

// ActivityText — строка состояния «чем занята программа».
func ActivityText(a app.Activity) string {
	names := map[string]string{
		app.Idle: "Простаивает", app.Loading: "Загрузка источников", app.Starting: "Запуск ядра",
		app.Checking: "Проверка серверов", app.ExitIP: "Определение выходного IP", app.Speed: "Замер скорости",
	}
	t := names[a.State]
	if t == "" {
		t = a.State
	}
	if a.State != app.Idle && a.Detail != "" {
		t += ": " + a.Detail
	}
	if a.Total > 0 {
		t += fmt.Sprintf(" (%d/%d)", a.Done, a.Total)
	}
	return t
}

// Percent — прогресс 0..100 (или -1, если задача без измеримого прогресса).
func Percent(a app.Activity) int {
	if a.State == app.Idle {
		return 0
	}
	if a.Total <= 0 {
		return -1
	}
	return a.Done * 100 / a.Total
}
