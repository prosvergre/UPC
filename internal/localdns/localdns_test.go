package localdns

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"proxycheck/internal/ssclient"
	"proxycheck/internal/ssuri"
)

// --- инфраструктура теста: свои SS- и DoH-сервера, без реального интернета ---

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// fakeSSServer поднимает игрушечный SS-сервер (обычный, не тестовый
// из ssclient — этот пакет не имеет доступа к его внутренним test-хелперам).
func fakeSSServer(t *testing.T, method, password string) (addr string, stop func()) {
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
				enc := ssclient.NewConn(c, method, password)
				hdr := make([]byte, 1)
				if _, err := io.ReadFull(enc, hdr); err != nil {
					return
				}
				if hdr[0] != 0x03 {
					return
				}
				l := make([]byte, 1)
				io.ReadFull(enc, l)
				domain := make([]byte, l[0])
				io.ReadFull(enc, domain)
				pb := make([]byte, 2)
				io.ReadFull(enc, pb)
				port := uint16(pb[0])<<8 | uint16(pb[1])
				target, err := net.Dial("tcp", fmt.Sprintf("%s:%d", string(domain), port))
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

// fakeDoHServer имитирует DoH-сервер: декодирует ?dns=<base64url>,
// проверяет содержимое (должно совпадать с отправленным клиентом
// "DNS-запросом") и отвечает фиксированным "DNS-ответом".
func fakeDoHServer(t *testing.T, wantQuery, fakeResponse []byte) (host string, port int, stop func()) {
	t.Helper()
	cert := generateSelfSignedCert(t)
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
				buf := make([]byte, 2048)
				n, _ := c.Read(buf)
				reqLine := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
				// reqLine: "GET /dns-query?dns=XXXX HTTP/1.1"
				parts := strings.Fields(reqLine)
				if len(parts) < 2 {
					return
				}
				u, err := url.Parse(parts[1])
				if err != nil {
					return
				}
				encoded := u.Query().Get("dns")
				decoded, err := base64.RawURLEncoding.DecodeString(encoded)
				if err != nil {
					return
				}
				if string(decoded) != string(wantQuery) {
					resp := "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
					io.WriteString(c, resp)
					return
				}
				resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\n\r\n%s",
					len(fakeResponse), fakeResponse)
				io.WriteString(c, resp)
			}(c)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	var portNum int
	fmt.Sscanf(p, "%d", &portNum)
	return h, portNum, func() { ln.Close() }
}

func TestResolveViaDoH(t *testing.T) {
	fakeQuery := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01}              // произвольные "байты DNS-запроса"
	fakeAnswer := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01} // произвольные "байты ответа"

	dohHostAddr, dohPortNum, stopDoH := fakeDoHServer(t, fakeQuery, fakeAnswer)
	defer stopDoH()

	method, password := "aes-256-gcm", "dns-test-pw"
	ssAddr, stopSS := fakeSSServer(t, method, password)
	defer stopSS()
	ssHost, ssPortStr, _ := net.SplitHostPort(ssAddr)
	var ssPort int
	fmt.Sscanf(ssPortStr, "%d", &ssPort)

	server := ssuri.Server{Host: ssHost, Port: ssPort, Method: method, Password: password}

	// подменяем dohHost/dohPort на наш фейковый сервер для теста —
	// поэтому дублируем resolveViaDoH-логику здесь напрямую, используя
	// ssclient.HTTPGetThroughTunnel с локальным хостом/портом
	encoded := base64URLEncode(fakeQuery)
	path := "/dns-query?dns=" + encoded
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	body, err := ssclient.HTTPGetThroughTunnelWithTLSConfig(server, dohHostAddr, dohPortNum, path,
		map[string]string{"Accept": "application/dns-message"}, tlsCfg, 3*time.Second)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if string(body) != string(fakeAnswer) {
		t.Fatalf("получили %x, ожидали %x", body, fakeAnswer)
	}
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestStartPortBusyGraceful(t *testing.T) {
	// занимаем UDP-порт заранее — имитирует "другую программу на 53"
	busyAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	busyConn, err := net.ListenUDP("udp", busyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer busyConn.Close()

	server := ssuri.Server{Host: "127.0.0.1", Port: 1, Method: "aes-256-gcm", Password: "x"}

	_, err = Start(busyConn.LocalAddr().String(), server, time.Second)
	if err == nil {
		t.Fatal("ожидалась ошибка (порт занят), но Start сообщил об успехе")
	}
	t.Logf("корректно поймана ошибка занятого порта (не паника, не крэш): %v", err)
}
