package relay_test

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"proxycheck/internal/relay"
	"proxycheck/internal/ssuri"
)

// TestDenyOnDeadUpstream проверяет главный баг, из-за которого Proxifier
// (и любой строгий SOCKS5-клиент) считал рабочие прокси мёртвыми:
// раньше SOCKS5-сервер отвечал клиенту "успех" ДО того, как реально
// подключался к Shadowsocks-серверу. Если апстрим был недоступен,
// клиент получал ложный "OK", а затем тишину вместо честного отказа.
func TestDenyOnDeadUpstream(t *testing.T) {
	// заведомо мёртвый апстрим — порт, на котором никто не слушает
	deadServer := ssuri.Server{Host: "127.0.0.1", Port: 1, Method: "aes-256-gcm", Password: "x"}

	mgr := relay.NewManager(nil, 500*time.Millisecond)
	ep, err := mgr.Start(deadServer, 18101)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll()

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", ep.LocalPort), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	_, err = dialer.Dial("tcp", "example.com:80")
	if err == nil {
		t.Fatal("ожидалась ошибка SOCKS5 (отказ), но Dial завершился успешно — клиент получил ложный 'успех'")
	}
	t.Logf("получен честный отказ, как и ожидалось: %v", err)
}
