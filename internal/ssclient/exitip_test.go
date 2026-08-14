package ssclient

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"proxycheck/internal/ssuri"
)

// fakeIPEchoTarget — TLS-сервер, отвечающий фиксированным IP как
// простым текстом — имитирует api.ipify.org для теста.
func fakeIPEchoTarget(t *testing.T, fakeIP string) (host string, port int, stop func()) {
	t.Helper()
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				c.Read(buf)
				resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(fakeIP), fakeIP)
				io.WriteString(c, resp)
			}(c)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	var portNum int
	fmt.Sscanf(p, "%d", &portNum)
	return h, portNum, func() { ln.Close() }
}

func TestDetectExitIPSuccess(t *testing.T) {
	wantIP := "203.0.113.42"
	ipHost, ipPort, stopIP := fakeIPEchoTarget(t, wantIP)
	defer stopIP()

	method, password := "aes-256-gcm", "exitip-pw"
	ssAddr, stopSS := fakeSSServerForVerify(t, method, password)
	defer stopSS()
	ssHost, ssPortStr, _ := net.SplitHostPort(ssAddr)
	var ssPort int
	fmt.Sscanf(ssPortStr, "%d", &ssPort)

	server := ssuri.Server{Host: ssHost, Port: ssPort, Method: method, Password: password}

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	got, err := detectExitIPWithConfig(server, ipHost, ipPort, tlsCfg, 3*time.Second)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if got != wantIP {
		t.Fatalf("получили IP %q, ожидали %q", got, wantIP)
	}
}

// TestDetectExitIPSlowClose — ключевой регрессионный тест. Раньше
// DetectExitIP читал тело ответа через io.ReadAll до EOF, то есть до
// закрытия TCP-соединения сервером. Некоторые реальные сервисы (в том
// числе за CDN) отправляют тело, но закрывают соединение с задержкой —
// в таком случае клиент, ждущий EOF, виснет до таймаута, хотя все
// нужные данные уже пришли. Этот тест специально не закрывает
// соединение сразу после ответа (спит некоторое время перед закрытием
// сервера), чтобы поймать именно эту ситуацию.
func TestDetectExitIPSlowClose(t *testing.T) {
	wantIP := "198.51.100.7"
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		c.Read(buf)
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(wantIP), wantIP)
		io.WriteString(c, resp)
		// НЕ закрываем соединение сразу — имитируем задержку перед FIN,
		// как иногда бывает у реальных сервисов за CDN
		time.Sleep(2 * time.Second)
	}()
	ipHost, ipPortStr, _ := net.SplitHostPort(ln.Addr().String())
	var ipPort int
	fmt.Sscanf(ipPortStr, "%d", &ipPort)

	method, password := "aes-256-gcm", "slowclose-pw"
	ssAddr, stopSS := fakeSSServerForVerify(t, method, password)
	defer stopSS()
	ssHost, ssPortStr, _ := net.SplitHostPort(ssAddr)
	var ssPort int
	fmt.Sscanf(ssPortStr, "%d", &ssPort)

	server := ssuri.Server{Host: ssHost, Port: ssPort, Method: method, Password: password}

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	// таймаут (1с) МЕНЬШЕ, чем задержка перед закрытием сервера (2с) —
	// если бы мы всё ещё ждали EOF, тест бы упал по таймауту
	got, err := detectExitIPWithConfig(server, ipHost, ipPort, tlsCfg, 1*time.Second)
	if err != nil {
		t.Fatalf("DetectExitIP не должен был ждать EOF и упасть по таймауту: %v", err)
	}
	if got != wantIP {
		t.Fatalf("получили IP %q, ожидали %q", got, wantIP)
	}
}
