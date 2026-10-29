package gui

import (
	"testing"
	"time"

	"proxycheck/internal/engine"
	"proxycheck/internal/node"
)

func TestNextStatusTransitions(t *testing.T) {
	cases := []struct {
		prev     liveStatus
		aliveNow bool
		want     liveStatus
	}{
		{statusUnknown, true, statusAlive},
		{statusUnknown, false, statusDead},
		{statusAlive, true, statusAlive},
		{statusAlive, false, statusDied}, // ключевой случай: был жив, стал недоступен -> "умер", не просто "мёртв"
		{statusDead, true, statusAlive},
		{statusDead, false, statusDead},
		{statusDied, true, statusAlive}, // ожил обратно после "умер" -> снова "жив"
		{statusDied, false, statusDied}, // остаётся "умер", не откатывается на "мёртв"
	}
	for _, c := range cases {
		got := nextStatus(c.prev, c.aliveNow)
		if got != c.want {
			t.Errorf("nextStatus(%v, %v) = %v, want %v", c.prev, c.aliveNow, got, c.want)
		}
	}
}

func TestStatusTextLabels(t *testing.T) {
	cases := map[liveStatus]string{
		statusUnknown: "—",
		statusAlive:   "жив",
		statusDead:    "мёртв",
		statusDied:    "умер",
	}
	for status, want := range cases {
		if got := status.text(); got != want {
			t.Errorf("status %v .text() = %q, want %q", status, got, want)
		}
	}
}

func TestSetFromResults_ImportantServerSurvivesAsDied(t *testing.T) {
	s := newAppState()
	srv := node.Node{Host: "127.0.0.1", Port: 1, Method: "aes-256-gcm", Password: "x"}

	// сначала сервер был жив и отмечен галочкой ("важный")
	s.setFromResults([]engine.Result{{Node: srv, Alive: true, Latency: 10 * time.Millisecond}})
	rows := s.rowsSnapshot()
	if len(rows) != 1 || rows[0].status != statusAlive {
		t.Fatalf("после первого скана ожидался 1 живой сервер, получили %+v", rows)
	}
	s.mu.Lock()
	rows[0].selected = true // помечаем "важным" вручную, как сделал бы пользователь галочкой
	s.mu.Unlock()

	// теперь тот же сервер не отвечает
	s.setFromResults([]engine.Result{{Node: srv, Alive: false}})
	rows = s.rowsSnapshot()
	if len(rows) != 1 {
		t.Fatalf("важный (отмеченный) сервер не должен пропадать из таблицы при смерти, строк: %d", len(rows))
	}
	if rows[0].status != statusDied {
		t.Fatalf("статус = %v, ожидался statusDied (был жив, стал недоступен)", rows[0].status)
	}
}

func TestSetFromResults_UnimportantDeadServerDropped(t *testing.T) {
	s := newAppState()
	srv := node.Node{Host: "127.0.0.1", Port: 2, Method: "aes-256-gcm", Password: "y"}

	// сервер из обычного массового скана, никогда не был отмечен,
	// не в закладках, не запущен — просто мёртвый шум
	s.setFromResults([]engine.Result{{Node: srv, Alive: false}})
	rows := s.rowsSnapshot()
	if len(rows) != 0 {
		t.Fatalf("неважный мёртвый сервер должен быть отброшен, получили %d строк", len(rows))
	}
}

func TestCompareHelpers(t *testing.T) {
	if cmpStrings("a", "b") >= 0 {
		t.Error("cmpStrings(\"a\",\"b\") должен быть отрицательным")
	}
	if cmpInt(5, 3) <= 0 {
		t.Error("cmpInt(5,3) должен быть положительным")
	}
	if cmpFloat(1.5, 1.5) != 0 {
		t.Error("cmpFloat равных значений должен быть 0")
	}
	if cmpDuration(time.Second, 2*time.Second) >= 0 {
		t.Error("cmpDuration(1s,2s) должен быть отрицательным")
	}
	if cmpBool(true, false) >= 0 {
		t.Error("cmpBool(true,false): true должно сортироваться первым (отрицательный результат)")
	}
	if cmpBool(false, true) <= 0 {
		t.Error("cmpBool(false,true) должен быть положительным")
	}
}

func TestDisplayName(t *testing.T) {
	withRemarks := &rowState{server: node.Node{Name: "my-server", Host: "1.2.3.4", Port: 443}}
	if displayName(withRemarks) != "my-server" {
		t.Errorf("ожидался Remarks, получили %q", displayName(withRemarks))
	}
	withoutRemarks := &rowState{server: node.Node{Proto: node.SS, Host: "1.2.3.4", Port: 443}}
	if displayName(withoutRemarks) != "ss 1.2.3.4:443" {
		t.Errorf("ожидался ID как fallback, получили %q", displayName(withoutRemarks))
	}
}

func TestSetFromResults_BookmarkedDeadServerKept(t *testing.T) {
	s := newAppState()
	srv := node.Node{Host: "127.0.0.1", Port: 3, Method: "aes-256-gcm", Password: "z"}

	s.setFromResults([]engine.Result{{Node: srv, Alive: true}})
	rows := s.rowsSnapshot()
	s.mu.Lock()
	rows[0].bookmarked = true
	s.mu.Unlock()

	s.setFromResults([]engine.Result{{Node: srv, Alive: false}})
	rows = s.rowsSnapshot()
	if len(rows) != 1 || rows[0].status != statusDied || !rows[0].bookmarked {
		t.Fatalf("закладка должна оставаться в таблице со статусом 'умер': %+v", rows)
	}
}
