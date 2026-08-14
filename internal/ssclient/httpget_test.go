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

func TestHTTPGetThroughTunnel(t *testing.T) {
	wantBody := []byte("hello from tunnel")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", mustSelfSignedTLSConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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
				resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(wantBody), wantBody)
				io.WriteString(c, resp)
			}(c)
		}
	}()
	targetHost, targetPortStr, _ := net.SplitHostPort(ln.Addr().String())
	var targetPort int
	fmt.Sscanf(targetPortStr, "%d", &targetPort)

	method, password := "aes-256-gcm", "httpget-pw"
	ssAddr, stopSS := fakeSSServerForVerify(t, method, password)
	defer stopSS()
	ssHost, ssPortStr, _ := net.SplitHostPort(ssAddr)
	var ssPort int
	fmt.Sscanf(ssPortStr, "%d", &ssPort)

	server := ssuri.Server{Host: ssHost, Port: ssPort, Method: method, Password: password}

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	body, err := HTTPGetThroughTunnelWithTLSConfig(server, targetHost, targetPort, "/test-path", map[string]string{"X-Test": "1"}, tlsCfg, 3*time.Second)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if string(body) != string(wantBody) {
		t.Fatalf("получили %q, ожидали %q", body, wantBody)
	}
}

func mustSelfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}
