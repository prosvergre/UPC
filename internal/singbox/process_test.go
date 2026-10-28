//go:build !windows

package singbox

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"proxycheck/internal/node"
)

func TestProcessAPIAndWatchdog(t *testing.T) {
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		t.Skip("SINGBOX_BIN не задан")
	}
	a, _ := node.Parse("socks5://127.0.0.1:1")
	b, _ := node.Parse("socks5://127.0.0.1:2")
	cfg, _, err := BuildConfig(Spec{Nodes: []node.Node{a, b}, Lines: []Line{{Port: 21090, NodeID: a.ID()}}, ClashAddr: "127.0.0.1:29091", Secret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	p := &Process{Binary: bin, WorkDir: t.TempDir(), Logf: t.Logf}
	if err := p.Start(cfg); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	ctx := context.Background()
	if err := WaitReady(ctx, "127.0.0.1:29091", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	api := &API{Addr: "127.0.0.1:29091", Secret: "s"}
	if err := api.Select(ctx, SelectorTag(21090), Tag(b)); err != nil {
		t.Fatal("select:", err)
	}
	if _, _, _, err := api.Connections(ctx); err != nil {
		t.Fatal("connections:", err)
	}
	if _, err := api.Delay(ctx, Tag(a), "http://www.gstatic.com/generate_204", 2*time.Second); err == nil {
		t.Fatal("delay через мёртвый апстрим должен давать ошибку")
	}
	// watchdog: убиваем процесс — должен подняться снова
	p.mu.Lock()
	pid := p.cmd.Process.Pid
	p.mu.Unlock()
	syscall.Kill(pid, syscall.SIGKILL)
	time.Sleep(500 * time.Millisecond)
	if err := WaitReady(ctx, "127.0.0.1:29091", 15*time.Second); err != nil {
		t.Fatal("watchdog не поднял процесс:", err)
	}
	if p.Restarts() < 1 {
		t.Fatal("restarts=0")
	}
}
