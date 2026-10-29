//go:build !windows

package relay

import (
	"net"
	"os"
	"testing"
	"time"

	"proxycheck/internal/engine"
	"proxycheck/internal/node"
)

func TestManagerLinesLifecycle(t *testing.T) {
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		t.Skip("SINGBOX_BIN не задан")
	}
	busy, err := net.Listen("tcp", "127.0.0.1:18099")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	a, _ := node.Parse("socks5://127.0.0.1:1")
	b, _ := node.Parse("socks5://127.0.0.2:1")
	m := NewManager([]node.Node{b}, time.Second)
	m.Listen = "127.0.0.1"
	m.SetEngine(engine.Config{Binary: bin, WorkDir: t.TempDir(), Logf: t.Logf})
	defer m.StopAll()

	ep, err := m.Start(a, 18099)
	if err != nil {
		t.Fatal(err)
	}
	if ep.LocalPort == 18099 || ep.LocalPort < 18099 {
		t.Fatalf("порт должен был сдвинуться: %d", ep.LocalPort)
	}
	if _, err := m.Start(a, 18099); err == nil {
		t.Fatal("повторный Start той же линии должен давать ошибку")
	}
	// порт линии реально слушает ядро
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(ep.LocalPort)), 2*time.Second)
	if err != nil {
		t.Fatal("линия не слушает:", err)
	}
	c.Close()

	// failover без перезапуска: переключаем линию на узел из пула
	if err := m.switchLine(ep, b); err != nil {
		t.Fatal("switchLine:", err)
	}
	if ep.CurrentServer().ID() != b.ID() {
		t.Fatal("линия не переключилась")
	}
	if err := m.Stop(a.ID()); err != nil {
		t.Fatal(err)
	}
	if len(m.Endpoints()) != 0 {
		t.Fatal("линий быть не должно")
	}
}

func itoa(n int) string {
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}
