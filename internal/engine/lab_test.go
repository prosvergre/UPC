//go:build !windows

package engine

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"proxycheck/internal/node"
)

// минимальный SOCKS5-сервер без авторизации, ходит напрямую
func startSocks(t *testing.T) int {
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
				buf := make([]byte, 262)
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				io.ReadFull(c, buf[:int(buf[1])])
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, buf[:4]); err != nil {
					return
				}
				var host string
				switch buf[3] {
				case 1:
					io.ReadFull(c, buf[:4])
					host = net.IP(buf[:4]).String()
				case 3:
					io.ReadFull(c, buf[:1])
					n := int(buf[0])
					io.ReadFull(c, buf[:n])
					host = string(buf[:n])
				case 4:
					io.ReadFull(c, buf[:16])
					host = net.IP(buf[:16]).String()
				}
				io.ReadFull(c, buf[:2])
				port := int(buf[0])<<8 | int(buf[1])
				up, err := net.Dial("tcp", net.JoinHostPort(host, itoa(port)))
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
	return ln.Addr().(*net.TCPAddr).Port
}

func itoa(n int) string { return string([]byte(func() []byte { return []byte(fmtInt(n)) }())) }
func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestLabEndToEnd(t *testing.T) {
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		t.Skip("SINGBOX_BIN не задан")
	}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/generate_204" {
			w.WriteHeader(204)
			return
		}
		w.Write([]byte("1.2.3.4"))
	}))
	defer web.Close()

	good, _ := node.Parse("socks5://127.0.0.1:" + itoa(startSocks(t)))
	dead, _ := node.Parse("socks5://127.0.0.1:1") // порт закрыт
	broken := node.Node{Proto: node.VLESS, Host: "h", Port: 443, UUID: "not-a-uuid"}

	lab, err := NewLab(Config{Binary: bin, WorkDir: t.TempDir(), Logf: t.Logf, LogLevel: os.Getenv("SB_LOG")}, []node.Node{good, dead, broken}, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()

	if lab.Skipped(broken.ID()) == nil {
		t.Error("битый vless должен быть исключён")
	}
	// ядро принимает для url-test только https, поэтому «живость» проверяем на
	// реальном gstatic — только если из окружения он достижим (в CI — да).
	res := lab.CheckAll(context.Background(), []node.Node{good, dead, broken}, 4, 5*time.Second, nil)
	if c, err := net.DialTimeout("tcp", "www.gstatic.com:443", 3*time.Second); err == nil {
		c.Close()
		if !res[0].Alive {
			t.Errorf("good должен быть жив: %v", res[0].Err)
		}
	} else {
		t.Log("gstatic недоступен — проверка живости пропущена")
	}
	if res[1].Alive || res[2].Alive {
		t.Errorf("dead/broken должны быть мертвы: %+v %+v", res[1], res[2])
	}

	// запрос через линию: проверяем, что трафик реально идёт через выбранный сервер
	err = lab.WithLane(context.Background(), good, func(addr string, c *http.Client) error {
		resp, err := c.Get(web.URL + "/ip")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if string(b) != "1.2.3.4" {
			t.Errorf("тело: %q", b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// линия через мёртвый сервер должна давать ошибку
	err = lab.WithLane(context.Background(), dead, func(addr string, c *http.Client) error {
		c.Timeout = 3 * time.Second
		_, err := c.Get(web.URL + "/ip")
		return err
	})
	if err == nil {
		t.Error("через мёртвый сервер запрос не должен проходить")
	}
}

func TestBadNodeIndexPatterns(t *testing.T) {
	a, _ := node.Parse("socks5://1.1.1.1:1")
	b, _ := node.Parse("socks5://2.2.2.2:1")
	w := node.Node{Proto: node.WireGuard, Host: "3.3.3.3", Port: 1}
	nodes := []node.Node{a, w, b}
	for msg, want := range map[string]string{
		"initialize outbound[1]: boom":               b.ID(), // wireguard — endpoint, в outbounds индекс 1 = b
		"decode config: outbounds[0].tls.x: bad":     a.ID(),
		"initialize endpoint[0]: invalid public_key": w.ID(),
		"что-то совсем другое":                       "",
	} {
		if got := badNode(msg, nodes, nil); got != want {
			t.Errorf("%q: got %q want %q", msg, got, want)
		}
	}
}
