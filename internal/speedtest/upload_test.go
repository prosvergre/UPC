package speedtest

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// мини-SOCKS5 без авторизации, ходит напрямую
func testSocks(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 262)
				io.ReadFull(c, b[:2])
				io.ReadFull(c, b[:int(b[1])])
				c.Write([]byte{5, 0})
				io.ReadFull(c, b[:4])
				var host string
				switch b[3] {
				case 1:
					io.ReadFull(c, b[:4])
					host = net.IP(b[:4]).String()
				case 3:
					io.ReadFull(c, b[:1])
					n := int(b[0])
					io.ReadFull(c, b[:n])
					host = string(b[:n])
				}
				io.ReadFull(c, b[:2])
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(b[0])<<8|int(b[1]))))
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestUploadFastServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}))
	defer srv.Close()
	res, err := Upload(testSocks(t), srv.URL, 0, 10*time.Second)
	if err != nil || res.Mbps <= 0 || res.Bytes == 0 {
		t.Fatalf("быстрый приёмник: %+v %v", res, err)
	}
}

// Медленный приёмник (~300 КБ/с): раньше один POST на 5 МБ упирался в таймаут и
// не давал вообще никакого числа; теперь первый же кусок даёт результат.
func TestUploadSlowServerStillMeasures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 30<<10)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				time.Sleep(100 * time.Millisecond) // 30 КБ / 0.1 с ≈ 300 КБ/с
			}
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	res, err := Upload(testSocks(t), srv.URL, 0, 6*time.Second)
	if err != nil || res.Mbps <= 0 {
		t.Fatalf("медленный приёмник должен дать число: %+v %v", res, err)
	}
	if res.Mbps > 10 {
		t.Fatalf("скорость нереалистично высокая для такого приёмника: %.1f", res.Mbps)
	}
}

func TestUploadErrorIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := Upload(testSocks(t), srv.URL, 0, 5*time.Second)
	if err == nil {
		t.Fatal("статус 403 должен давать ошибку")
	}
	t.Log(err)
}
