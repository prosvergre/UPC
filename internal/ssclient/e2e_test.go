package ssclient_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"proxycheck/internal/socks5"
	"proxycheck/internal/ssclient"
	"proxycheck/internal/ssuri"
)

// Поднимает игрушечный "SS-сервер": слушает TCP, оборачивает
// шифрованием тем же способом, что и клиент (aeadConn симметричен),
// читает адрес назначения, потом просто эхо всё, что придёт.
func fakeSSServer(t *testing.T, method, password string) (addr string, stop func()) {
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
				// читаем адрес назначения (ATYP+ADDR+PORT) - для IPv4 domain = 1+4+2=7 байт
				hdr := make([]byte, 1)
				io.ReadFull(enc, hdr)
				switch hdr[0] {
				case 0x01:
					rest := make([]byte, 6)
					io.ReadFull(enc, rest)
				case 0x03:
					l := make([]byte, 1)
					io.ReadFull(enc, l)
					rest := make([]byte, int(l[0])+2)
					io.ReadFull(enc, rest)
				}
				// эхо
				io.Copy(enc, enc)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestE2EEcho(t *testing.T) {
	for _, method := range []string{
		"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
		"aes-128-cfb", "aes-256-cfb", "aes-192-ctr", "aes-256-ctr",
	} {
		t.Run(method, func(t *testing.T) {
			password := "test-password-123"
			addr, stop := fakeSSServer(t, method, password)
			defer stop()

			host, portStr, _ := net.SplitHostPort(addr)
			var port int
			fmt.Sscanf(portStr, "%d", &port)

			server := ssuri.Server{Host: host, Port: port, Method: method, Password: password}

			// целевой адрес: IPv4 1.2.3.4:80
			target := []byte{0x01, 1, 2, 3, 4, 0, 80}

			conn, err := ssclient.Dial(server, target, 3*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			payload := bytes.Repeat([]byte("Hello, Shadowsocks! "), 1000) // > одного чанка не нужно, но проверим и большие
			go func() {
				conn.Write(payload)
			}()

			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if !bytes.Equal(buf, payload) {
				t.Fatalf("echo mismatch")
			}
		})
	}
}

func TestSocks5Parsing(t *testing.T) {
	// клиент <-> наш socks5.Accept
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan *socks5.Request, 1)
	go func() {
		c, _ := ln.Accept()
		req, err := socks5.Accept(c)
		if err != nil {
			t.Error(err)
			return
		}
		if err := req.Grant(); err != nil {
			t.Error(err)
			return
		}
		done <- req
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// greeting: ver5, 1 method, no-auth
	c.Write([]byte{0x05, 0x01, 0x00})
	reply := make([]byte, 2)
	io.ReadFull(c, reply)
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("bad greeting reply: %v", reply)
	}
	// CONNECT to example.com:443 (domain)
	domain := "example.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	req = append(req, domain...)
	req = append(req, 0x01, 0xBB) // port 443
	c.Write(req)

	connReply := make([]byte, 10)
	io.ReadFull(c, connReply)
	if connReply[1] != 0x00 {
		t.Fatalf("connect not granted: %v", connReply)
	}

	r := <-done
	if r.TargetHost != domain || r.TargetPort != 443 {
		t.Fatalf("parsed wrong target: %s:%d", r.TargetHost, r.TargetPort)
	}
	expectedRaw := append([]byte{0x03, byte(len(domain))}, append([]byte(domain), 0x01, 0xBB)...)
	if !bytes.Equal(r.RawAddr, expectedRaw) {
		t.Fatalf("raw addr mismatch: got %x want %x", r.RawAddr, expectedRaw)
	}
}
