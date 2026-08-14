package speedtest_test

import (
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

func TestUploadThroughFullStack(t *testing.T) {
	var receivedBytes int64
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		receivedBytes = n
		w.WriteHeader(http.StatusOK)
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
	method, password := "aes-256-gcm", "upload-test-pw"
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
	localPort := 18095
	if _, err := mgr.Start(server, localPort); err != nil {
		t.Fatal(err)
	}
	defer mgr.StopAll()

	uploadURL := fmt.Sprintf("http://%s:%d/", httpHost, httpPort)
	const size = 512 * 1024
	res, err := speedtest.Upload(fmt.Sprintf("127.0.0.1:%d", localPort), uploadURL, size, 10*time.Second)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if res.Bytes != size {
		t.Fatalf("Result.Bytes = %d, ожидалось %d", res.Bytes, size)
	}
	if receivedBytes != size {
		t.Fatalf("сервер реально получил %d байт, ожидалось %d", receivedBytes, size)
	}
	t.Logf("отправлено и подтверждено сервером %d байт за %v (%.2f Мбит/с)", res.Bytes, res.Duration, res.Mbps)
}
