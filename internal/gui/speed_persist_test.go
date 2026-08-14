package gui

import (
	"testing"
	"time"

	"proxycheck/internal/checker"
	"proxycheck/internal/ssuri"
)

func TestSpeedAndExitIPSurviveSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/settings.json"

	s := newAppState()
	s.settingsPath = path
	srv := ssuri.Server{Host: "127.0.0.1", Port: 1, Method: "aes-256-gcm", Password: "x"}

	s.setFromResults([]checker.Result{{Server: srv, Alive: true, Latency: 50 * time.Millisecond}})
	rows := s.rowsSnapshot()
	if len(rows) != 1 {
		t.Fatalf("ожидалась 1 строка, получили %d", len(rows))
	}
	s.mu.Lock()
	rows[0].speedMbps = 42.5
	rows[0].speedDone = true
	rows[0].speedAttempted = true
	rows[0].ulSpeedMbps = 7.3
	rows[0].ulSpeedDone = true
	rows[0].ulSpeedAttempted = true
	rows[0].exitIP = "203.0.113.9"
	rows[0].exitIPDone = true
	rows[0].exitIPAttempted = true
	s.mu.Unlock()

	if err := s.saveSettings(); err != nil {
		t.Fatalf("saveSettings: %v", err)
	}

	// имитируем новый запуск программы: свежий appState, читающий тот же файл
	s2 := newAppState()
	s2.settingsPath = path
	loaded := s2.loadSettings()
	s2.loadRowsFromSettings(loaded)

	rows2 := s2.rowsSnapshot()
	if len(rows2) != 1 {
		t.Fatalf("после загрузки ожидалась 1 строка, получили %d", len(rows2))
	}
	r := rows2[0]
	if r.speedMbps != 42.5 || !r.speedDone {
		t.Errorf("скорость скачивания не восстановилась: mbps=%v done=%v", r.speedMbps, r.speedDone)
	}
	if r.ulSpeedMbps != 7.3 || !r.ulSpeedDone {
		t.Errorf("скорость отдачи не восстановилась: mbps=%v done=%v", r.ulSpeedMbps, r.ulSpeedDone)
	}
	if r.exitIP != "203.0.113.9" || !r.exitIPDone {
		t.Errorf("выходной IP не восстановился: ip=%v done=%v", r.exitIP, r.exitIPDone)
	}
}

// TestFailedSpeedAttemptSurvivesRoundTrip проверяет, что различие
// "не мерили" / "мерили, но не вышло" тоже переживает перезапуск —
// не только успешные замеры.
func TestFailedSpeedAttemptSurvivesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/settings.json"

	s := newAppState()
	s.settingsPath = path
	srv := ssuri.Server{Host: "127.0.0.1", Port: 2, Method: "aes-256-gcm", Password: "y"}

	s.setFromResults([]checker.Result{{Server: srv, Alive: true}})
	rows := s.rowsSnapshot()
	s.mu.Lock()
	rows[0].speedAttempted = true // попытка была, но speedDone остаётся false — замер провалился
	s.mu.Unlock()

	if err := s.saveSettings(); err != nil {
		t.Fatalf("saveSettings: %v", err)
	}

	s2 := newAppState()
	s2.settingsPath = path
	loaded := s2.loadSettings()
	s2.loadRowsFromSettings(loaded)

	r := s2.rowsSnapshot()[0]
	if r.speedDone {
		t.Errorf("speedDone должен остаться false (замер не удался)")
	}
	if !r.speedAttempted {
		t.Errorf("speedAttempted должен восстановиться как true — иначе не отличить 'не мерили' от 'не вышло'")
	}
}
