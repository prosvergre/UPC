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

// fakeSSServerForVerify поднимает игрушечный SS-сервер, который
// расшифровывает трафик ЗАДАННЫМ методом/паролем, разбирает адрес
// назначения и реально коннектится туда (как настоящий SS-сервер).
// Если фактический пароль клиента не совпадает — расшифровка на
// сервере будет мусором, соединение просто зависнет без ответа —
// именно то поведение, которое VerifyHandshake должен поймать по
// таймауту.
func fakeSSServerForVerify(t *testing.T, method, password string) (addr string, stop func()) {
	t.Helper()
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
				enc := NewConn(c, method, password)
				hdr := make([]byte, 1)
				if _, err := io.ReadFull(enc, hdr); err != nil {
					return
				}
				var host string
				var port uint16
				switch hdr[0] {
				case 0x01:
					ip := make([]byte, 4)
					if _, err := io.ReadFull(enc, ip); err != nil {
						return
					}
					pb := make([]byte, 2)
					if _, err := io.ReadFull(enc, pb); err != nil {
						return
					}
					host = net.IP(ip).String()
					port = uint16(pb[0])<<8 | uint16(pb[1])
				case 0x03:
					l := make([]byte, 1)
					if _, err := io.ReadFull(enc, l); err != nil {
						return
					}
					domain := make([]byte, l[0])
					if _, err := io.ReadFull(enc, domain); err != nil {
						return
					}
					pb := make([]byte, 2)
					if _, err := io.ReadFull(enc, pb); err != nil {
						return
					}
					host = string(domain)
					port = uint16(pb[0])<<8 | uint16(pb[1])
				default:
					return
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

// fakeTLSTarget — настоящий TLS-сервер (самоподписанный сертификат),
// отвечающий фиксированной HTTP-строкой поверх TLS — имитирует
// www.gstatic.com для теста, без обращения к реальному интернету.
func fakeTLSTarget(t *testing.T) (host string, port int, stop func()) {
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
				io.WriteString(c, "HTTP/1.1 204 No Content\r\n\r\n")
			}(c)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	var portNum int
	fmt.Sscanf(p, "%d", &portNum)
	return h, portNum, func() { ln.Close() }
}

func TestVerifyHandshakeSuccess(t *testing.T) {
	httpHost, httpPort, stopHTTP := fakeTLSTarget(t)
	defer stopHTTP()

	method, password := "aes-256-gcm", "correct-password"
	ssAddr, stopSS := fakeSSServerForVerify(t, method, password)
	defer stopSS()
	ssHost, ssPortStr, _ := net.SplitHostPort(ssAddr)
	var ssPort int
	fmt.Sscanf(ssPortStr, "%d", &ssPort)

	server := ssuri.Server{Host: ssHost, Port: ssPort, Method: method, Password: password}

	tlsCfg := &tls.Config{InsecureSkipVerify: true} // самоподписанный сертификат теста
	latency, err := verifyHandshakeWithConfig(server, httpHost, httpPort, tlsCfg, 3*time.Second)
	if err != nil {
		t.Fatalf("ожидался успех, получена ошибка: %v", err)
	}
	t.Logf("глубокая проверка (TLS) прошла успешно за %v", latency)
}

func TestVerifyHandshakeWrongPassword(t *testing.T) {
	httpHost, httpPort, stopHTTP := fakeTLSTarget(t)
	defer stopHTTP()

	method := "aes-256-gcm"
	ssAddr, stopSS := fakeSSServerForVerify(t, method, "real-password-on-server")
	defer stopSS()
	ssHost, ssPortStr, _ := net.SplitHostPort(ssAddr)
	var ssPort int
	fmt.Sscanf(ssPortStr, "%d", &ssPort)

	server := ssuri.Server{Host: ssHost, Port: ssPort, Method: method, Password: "wrong-password"}

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	_, err := verifyHandshakeWithConfig(server, httpHost, httpPort, tlsCfg, 1*time.Second)
	if err == nil {
		t.Fatal("ожидалась ошибка при неверном пароле, но VerifyHandshake сообщил об успехе")
	}
	t.Logf("корректно поймана ошибка при неверном пароле: %v", err)
}
