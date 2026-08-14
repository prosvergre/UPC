package relay_test

import (
	"net"
	"strconv"
	"testing"
	"time"

	"proxycheck/internal/relay"
	"proxycheck/internal/ssuri"
)

func TestHealthLoopFailover(t *testing.T) {
	// "живой" резервный сервер — просто TCP-порт, который слушает (checker.CheckOne
	// проверяет только TCP-доступность, этого достаточно для теста failover-логики)
	deadServer := ssuri.Server{Host: "127.0.0.1", Port: 1, Method: "aes-256-gcm", Password: "x"} // порт 1 — почти наверняка закрыт
	goodAddr, stopGood := echoTarget(t)
	defer stopGood()
	goodHost, goodPortStr, err := net.SplitHostPort(goodAddr)
	if err != nil {
		t.Fatal(err)
	}
	goodPort, err := strconv.Atoi(goodPortStr)
	if err != nil {
		t.Fatal(err)
	}
	goodServer := ssuri.Server{Host: goodHost, Port: goodPort, Method: "aes-256-gcm", Password: "x"}

	pool := []ssuri.Server{goodServer}

	mgr := relay.NewManager(pool, 500*time.Millisecond)
	ep, err := mgr.Start(deadServer, 18081)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll()

	stop := make(chan struct{})
	defer close(stop)
	go mgr.RunHealthLoop(100*time.Millisecond, 300*time.Millisecond, 2, stop)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ep.CurrentServer().ID() == goodServer.ID() {
			return // failover сработал
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("failover не произошёл за 5с, текущий сервер: %s", ep.CurrentServer().ID())
}
