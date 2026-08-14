package relay_test

import (
	"net"
	"testing"
	"time"

	"proxycheck/internal/relay"
	"proxycheck/internal/ssuri"
)

func TestStartPortAutoBump(t *testing.T) {
	// занимаем порт заранее сторонним листенером — имитирует "другую программу"
	busy, err := net.Listen("tcp", "127.0.0.1:18099")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	mgr := relay.NewManager(nil, time.Second)
	server := ssuri.Server{Host: "127.0.0.1", Port: 1, Method: "aes-256-gcm", Password: "x"}

	ep, err := mgr.Start(server, 18099)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll()

	if ep.LocalPort == 18099 {
		t.Fatalf("ожидался автоподъём порта, но получили тот же самый занятый порт")
	}
	if ep.LocalPort <= 18099 {
		t.Fatalf("неожиданный порт: %d (ожидался > 18099)", ep.LocalPort)
	}
	t.Logf("занятый порт 18099 -> фактически поднят на %d", ep.LocalPort)
}
