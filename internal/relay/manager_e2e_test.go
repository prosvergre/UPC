package relay_test

import (
	"bytes"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"testing"
	"time"

	"proxycheck/internal/relay"
	"proxycheck/internal/ssclient"
	"proxycheck/internal/ssuri"
)

// echoTarget — обычный TCP-сервер, изображающий "конечный сайт", на
// который прокси должен довести соединение и который просто отвечает эхом.
func echoTarget(t *testing.T) (addr string, stop func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// fakeSSServer2 — Shadowsocks-сервер понарошку: расшифровывает,
// узнаёт целевой адрес и реально коннектится туда (как настоящий SS-сервер).
func fakeSSServer2(t *testing.T, method, password string) (addr string, stop func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				enc := ssclient.NewConn(c, method, password)
				hdr := make([]byte, 1)
				if _, err := io.ReadFull(enc, hdr); err != nil {
					return
				}
				var host string
				var port uint16
				switch hdr[0] {
				case 0x01:
					ip := make([]byte, 4)
					io.ReadFull(enc, ip)
					portB := make([]byte, 2)
					io.ReadFull(enc, portB)
					host = net.IP(ip).String()
					port = uint16(portB[0])<<8 | uint16(portB[1])
				case 0x03:
					l := make([]byte, 1)
					io.ReadFull(enc, l)
					domain := make([]byte, l[0])
					io.ReadFull(enc, domain)
					portB := make([]byte, 2)
					io.ReadFull(enc, portB)
					host = string(domain)
					port = uint16(portB[0])<<8 | uint16(portB[1])
				}
				target, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
				if err != nil {
					return
				}
				defer target.Close()
				go io.Copy(target, enc)
				io.Copy(enc, target)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestManagerFullPath(t *testing.T) {
	targetAddr, stopTarget := echoTarget(t)
	defer stopTarget()
	targetHost, targetPortStr, _ := net.SplitHostPort(targetAddr)
	var targetPort int
	fmt.Sscanf(targetPortStr, "%d", &targetPort)

	ssAddr, stopSS := fakeSSServer2(t, "aes-256-gcm", "manager-test-pw")
	defer stopSS()
	ssHost, ssPortStr, _ := net.SplitHostPort(ssAddr)
	var ssPort int
	fmt.Sscanf(ssPortStr, "%d", &ssPort)

	server := ssuri.Server{Host: ssHost, Port: ssPort, Method: "aes-256-gcm", Password: "manager-test-pw", Remarks: "test-server"}

	mgr := relay.NewManager(nil, 3*time.Second)
	localPort := 18080
	ep, err := mgr.Start(server, localPort)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll()
	if ep.LocalPort != localPort {
		t.Fatalf("unexpected local port")
	}

	// подключаемся как обычный SOCKS5-клиент (golang.org/x/net/proxy) через наш локальный порт
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort))
	if err != nil {
		t.Fatalf("socks5 dial через наш прокси: %v", err)
	}
	defer conn.Close()

	msg := bytes.Repeat([]byte("full-path-ok "), 500)
	go conn.Write(msg)

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("data mismatch")
	}
}
