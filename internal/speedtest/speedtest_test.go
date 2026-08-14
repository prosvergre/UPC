package speedtest_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"proxycheck/internal/relay"
	"proxycheck/internal/speedtest"
	"proxycheck/internal/ssclient"
	"proxycheck/internal/ssuri"
)

// runDownloadTest прогоняет полный стек (HTTP-сервер -> фейковый SS ->
// relay -> speedtest.Download) с указанным методом шифрования и
// размером полезной нагрузки, проверяя ЦЕЛОСТНОСТЬ данных (не только
// их количество) через SHA-256 хэш — это ловит именно тот класс багов,
// когда шифр слегка портит данные на больших объёмах, но не на
// маленьких тестовых payload'ах (как раз то, что не покрывали прежние
// тесты для stream-шифров: они гоняли только пары КБ).
func runDownloadTest(t *testing.T, method string, payloadSize int, localPort int) {
	t.Helper()

	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(payload)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer httpSrv.Close()

	httpHost, httpPortStr, _ := net.SplitHostPort(httpSrv.Listener.Addr().String())
	var httpPort int
	fmt.Sscanf(httpPortStr, "%d", &httpPort)

	ssLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ssLn.Close()
	password := "speedtest-pw"
	go func() {
		for {
			c, err := ssLn.Accept()
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
				if hdr[0] == 0x01 {
					ip := make([]byte, 4)
					io.ReadFull(enc, ip)
					pb := make([]byte, 2)
					io.ReadFull(enc, pb)
					host = net.IP(ip).String()
					port = uint16(pb[0])<<8 | uint16(pb[1])
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

	ssHost, ssPortStr, _ := net.SplitHostPort(ssLn.Addr().String())
	var ssPort int
	fmt.Sscanf(ssPortStr, "%d", &ssPort)

	server := ssuri.Server{Host: ssHost, Port: ssPort, Method: method, Password: password}
	mgr := relay.NewManager(nil, 5*time.Second)
	if _, err := mgr.Start(server, localPort); err != nil {
		t.Fatal(err)
	}
	defer mgr.StopAll()

	// проверяем данные напрямую (не через speedtest.Download, который
	// считает только количество байт) — качаем через тот же прокси и
	// сверяем SHA-256 всего полученного тела с оригиналом
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// SOCKS5 handshake + CONNECT к тестовому HTTP-серверу
	conn.Write([]byte{0x05, 0x01, 0x00})
	reply := make([]byte, 2)
	io.ReadFull(conn, reply)
	if reply[1] != 0x00 {
		t.Fatalf("SOCKS5 greeting отклонён: %v", reply)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, net.ParseIP(httpHost).To4()...)
	req = append(req, byte(httpPort>>8), byte(httpPort))
	conn.Write(req)
	connReply := make([]byte, 10)
	io.ReadFull(conn, connReply)
	if connReply[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT отклонён: %v", connReply)
	}

	httpReq := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\n\r\n", httpHost)
	if _, err := io.WriteString(conn, httpReq); err != nil {
		t.Fatal(err)
	}

	full, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("чтение ответа: %v", err)
	}
	// отделяем HTTP-заголовки от тела
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(full, sep)
	if idx == -1 {
		t.Fatalf("не нашли конец HTTP-заголовков в ответе")
	}
	body := full[idx+len(sep):]

	if len(body) != payloadSize {
		t.Fatalf("[%s] получено %d байт тела, ожидалось %d", method, len(body), payloadSize)
	}
	gotHash := sha256.Sum256(body)
	if gotHash != wantHash {
		t.Fatalf("[%s] SHA-256 не совпадает — данные повреждены при передаче через шифр (получено %d байт)", method, len(body))
	}
	t.Logf("[%s] %d байт переданы БЕЗ ПОВРЕЖДЕНИЙ (SHA-256 совпал)", method, len(body))
}

// TestDataIntegrityAllMethods — ключевой тест по мотивам репорта:
// один из живых (по глубокой проверке) серверов давал "—" при замере
// скорости. Проверяем гипотезу, что дело в повреждении данных на
// больших объёмах для КОНКРЕТНЫХ методов шифрования (особенно
// stream-шифры вроде aes-256-cfb, которые раньше проверялись только
// на маленьких payload'ах в e2e_test.go).
func TestDataIntegrityAllMethods(t *testing.T) {
	methods := []string{
		"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
		"aes-128-cfb", "aes-256-cfb", "aes-128-ctr", "aes-256-ctr",
	}
	const payloadSize = 5 * 1024 * 1024 // 5 МБ — достаточно, чтобы пройти много чанков/блоков
	port := 18100
	for _, method := range methods {
		method := method
		port := port
		t.Run(method, func(t *testing.T) {
			runDownloadTest(t, method, payloadSize, port)
		})
		port++
	}
}

func TestDownloadThroughFullStack(t *testing.T) {
	const payloadSize = 2 * 1024 * 1024 // 2 МБ
	payload := bytes.Repeat([]byte{0xAB}, payloadSize)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer httpSrv.Close()

	httpHost, httpPortStr, _ := net.SplitHostPort(httpSrv.Listener.Addr().String())
	var httpPort int
	fmt.Sscanf(httpPortStr, "%d", &httpPort)

	ssLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ssLn.Close()
	method, password := "aes-256-gcm", "speedtest-pw"
	go func() {
		for {
			c, err := ssLn.Accept()
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
				if hdr[0] == 0x01 {
					ip := make([]byte, 4)
					io.ReadFull(enc, ip)
					pb := make([]byte, 2)
					io.ReadFull(enc, pb)
					host = net.IP(ip).String()
					port = uint16(pb[0])<<8 | uint16(pb[1])
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

	ssHost, ssPortStr, _ := net.SplitHostPort(ssLn.Addr().String())
	var ssPort int
	fmt.Sscanf(ssPortStr, "%d", &ssPort)

	server := ssuri.Server{Host: ssHost, Port: ssPort, Method: method, Password: password}
	mgr := relay.NewManager(nil, 3*time.Second)
	localPort := 18090
	if _, err := mgr.Start(server, localPort); err != nil {
		t.Fatal(err)
	}
	defer mgr.StopAll()

	testURL := fmt.Sprintf("http://%s:%d/", httpHost, httpPort)
	res, err := speedtest.Download(fmt.Sprintf("127.0.0.1:%d", localPort), testURL, 10*time.Second)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Bytes != payloadSize {
		t.Fatalf("скачано %d байт, ожидалось %d", res.Bytes, payloadSize)
	}
	t.Logf("скачано %d байт за %v (%.2f Мбит/с)", res.Bytes, res.Duration, res.Mbps)
}
