package winui

import (
	"testing"

	"proxycheck/internal/app"
)

func TestCellTextAndSort(t *testing.T) {
	rows := []app.Row{
		{Name: "🇩🇪 de-2", Status: app.StatusAlive, LatencyMs: 300, Country: "DE", Host: "b", Port: 1, Summary: "ws · tls", ExitErr: "x"},
		{Name: "gb", Status: app.StatusAlive, LatencyMs: 90, Country: "GB", Host: "a", Port: 2, ExitIP: "1.2.3.4", SpeedMbps: 12.34, Pinned: true},
		{Name: "dead", Status: app.StatusDead, LatencyMs: 5, SpeedErr: "boom"},
	}
	if got := CellText(rows[0], 2); got != "de-2" {
		t.Errorf("флаг-эмодзи в имени должен скрываться: %q", got)
	}
	if got := CellText(rows[1], 2); got != "gb  [ручной]" {
		t.Errorf("закрепление: %q", got)
	}
	if CellText(rows[0], 0) != FlagPad+"DE" || CellText(rows[2], 0) != "" {
		t.Error("колонка страны")
	}
	if CellText(rows[0], 7) != "не определён" || CellTip(rows[0], 7) != "x" {
		t.Error("ошибка IP у живого")
	}
	if CellText(rows[2], 6) != "" || CellText(rows[1], 6) != "90 мс" {
		t.Error("задержка только у живых")
	}
	if CellText(rows[2], 8) != "ошибка" || CellTip(rows[2], 8) != "boom" || CellText(rows[1], 8) != "12.3" {
		t.Error("скорость")
	}
	SortRows(rows, 6, true) // по задержке: 90, 300, мёртвый в конце
	if rows[0].Name != "gb" || rows[1].Name != "🇩🇪 de-2" || rows[2].Name != "dead" {
		t.Errorf("сортировка по задержке: %v %v %v", rows[0].Name, rows[1].Name, rows[2].Name)
	}
	SortRows(rows, 8, true) // по скорости: быстрые первыми
	if rows[0].Name != "gb" {
		t.Errorf("сортировка по скорости: %v", rows[0].Name)
	}
	SortRows(rows, 5, true) // по адресу
	if rows[0].Host == "b" {
		t.Error("сортировка по адресу")
	}
}

func TestActivity(t *testing.T) {
	a := app.Activity{State: app.Checking, Detail: "проверка серверов", Done: 50, Total: 200}
	if ActivityText(a) != "Проверка серверов: проверка серверов (50/200)" || Percent(a) != 25 {
		t.Error(ActivityText(a), Percent(a))
	}
	if ActivityText(app.Activity{State: app.Idle}) != "Простаивает" || Percent(app.Activity{State: app.Idle}) != 0 {
		t.Error("idle")
	}
	if Percent(app.Activity{State: app.Loading}) != -1 {
		t.Error("без прогресса")
	}
}

func TestBusyAndUploadErrorCells(t *testing.T) {
	r := app.Row{Status: app.StatusAlive, Busy: "speed"}
	if CellText(r, 8) != "замер…" || CellText(r, 9) != "замер…" {
		t.Error("индикатор замера")
	}
	r.Busy = "queued"
	if CellText(r, 8) != "в очереди" {
		t.Error("очередь")
	}
	r.Busy = "check"
	if CellText(r, 1) != "проверка…" {
		t.Error("проверка")
	}
	r = app.Row{Status: app.StatusAlive, SpeedMbps: 10, UlErr: "таймаут"}
	if CellText(r, 8) != "10.0" || CellText(r, 9) != "ошибка" || CellTip(r, 9) != "таймаут" {
		t.Error("ошибка отдачи при удачном скачивании")
	}
}

func TestCheckedFirst(t *testing.T) {
	rows := []app.Row{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	checked := map[string]bool{"b": true, "d": true}
	CheckedFirst(rows, func(id string) bool { return checked[id] })
	got := rows[0].ID + rows[1].ID + rows[2].ID + rows[3].ID
	if got != "bdac" {
		t.Errorf("отмеченные наверх с сохранением порядка: %s", got)
	}
}
