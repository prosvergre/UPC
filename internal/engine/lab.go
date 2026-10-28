// Package engine — слой между GUI/CLI и ядром sing-box: проверка серверов
// пачкой в одном процессе, HTTP-запросы через выбранный сервер (для IP и
// скорости), общий жизненный цикл. Один Lab = один процесс sing-box на
// всю пачку серверов, а не по процессу на каждый сервер.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"proxycheck/internal/node"
	"proxycheck/internal/singbox"
)

// Config — общие параметры движка.
type Config struct {
	Binary   string // путь к sing-box(.exe)
	WorkDir  string // каталог для временных конфигов
	LogLevel string // уровень логов sing-box (по умолчанию warn)
	Logf     func(format string, args ...interface{})
}

func (c Config) logf(f string, a ...interface{}) {
	if c.Logf != nil {
		c.Logf(f, a...)
	}
}

// FindBinary ищет sing-box рядом с исполняемым файлом программы, затем в PATH.
func FindBinary() (string, error) {
	name := "sing-box"
	if os.PathSeparator == '\\' {
		name = "sing-box.exe"
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if p, err := lookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("не найден %s (положите рядом с программой)", name)
}

// FreePort находит свободный локальный TCP-порт.
func FreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Lab — временный процесс sing-box, в котором загружены все серверы пачки.
type Lab struct {
	cfg     Config
	proc    *singbox.Process
	api     *singbox.API
	skipped map[string]error
	nodes   map[string]node.Node

	lanes   chan lane
	closeMu sync.Once

	// CheckURL — адрес для проверки живости (по умолчанию DefaultTestURL).
	CheckURL string
}

type lane struct {
	port     int
	selector string
	client   *http.Client
}

var badIdxRe = regexp.MustCompile(`(outbound|endpoint)\[(\d+)\]`)

// NewLab запускает sing-box с серверами nodes и lanes линиями для HTTP-запросов.
// Серверы, на которых ядро не стартует, исключаются и доступны через Skipped.
func NewLab(cfg Config, nodes []node.Node, lanes int) (*Lab, error) {
	if lanes <= 0 {
		lanes = 4
	}
	clashPort, err := FreePort()
	if err != nil {
		return nil, err
	}
	var specLines []singbox.Line
	var ports []int
	for i := 0; i < lanes; i++ {
		p, err := FreePort()
		if err != nil {
			return nil, err
		}
		for contains(ports, p) || p == clashPort {
			if p, err = FreePort(); err != nil {
				return nil, err
			}
		}
		ports = append(ports, p)
		specLines = append(specLines, singbox.Line{Port: p})
	}
	secret := randHex(8)
	clash := "127.0.0.1:" + strconv.Itoa(clashPort)
	l := &Lab{cfg: cfg, api: &singbox.API{Addr: clash, Secret: secret}, skipped: map[string]error{}, nodes: map[string]node.Node{}, lanes: make(chan lane, lanes)}

	work := filepath.Join(cfg.WorkDir, "lab-"+randHex(4))
	cur := append([]node.Node(nil), nodes...)
	for attempt := 0; attempt < 40; attempt++ {
		if len(cur) == 0 {
			return nil, fmt.Errorf("нет пригодных серверов")
		}
		for i := range specLines {
			specLines[i].NodeID = cur[0].ID()
		}
		b, skipped, err := singbox.BuildConfig(singbox.Spec{Nodes: cur, Lines: specLines, ClashAddr: clash, Secret: secret, LogLevel: cfg.LogLevel})
		if err != nil {
			return nil, err
		}
		for id, e := range skipped {
			l.skipped[id] = e
		}
		l.proc = &singbox.Process{Binary: cfg.Binary, WorkDir: work, Logf: cfg.Logf}
		err = l.proc.Start(b)
		if err == nil {
			break
		}
		// ядро отвергло конфиг: пробуем вычислить плохой сервер по индексу и выкинуть
		bad := badNode(err.Error(), cur, skipped)
		if bad == "" {
			return nil, err
		}
		l.skipped[bad] = fmt.Errorf("ядро отвергло сервер: %v", firstLine(err.Error()))
		cfg.logf("исключён сервер %s: %s", bad, firstLine(err.Error()))
		next := cur[:0:0]
		for _, n := range cur {
			if n.ID() != bad {
				next = append(next, n)
			}
		}
		cur = next
		l.proc = nil
		if attempt == 39 {
			return nil, err
		}
	}
	for _, n := range cur {
		l.nodes[n.ID()] = n
	}
	if err := singbox.WaitReady(context.Background(), clash, 20*time.Second); err != nil {
		l.proc.Stop()
		return nil, err
	}
	for _, sl := range specLines {
		proxy, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(sl.Port))
		l.lanes <- lane{port: sl.Port, selector: singbox.SelectorTag(sl.Port), client: &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true},
		}}
	}
	return l, nil
}

// badNode определяет по тексту ошибки ядра ID сервера (индекс outbound/endpoint в конфиге).
func badNode(msg string, nodes []node.Node, skipped map[string]error) string {
	m := badIdxRe.FindStringSubmatch(msg)
	if m == nil {
		return ""
	}
	idx, _ := strconv.Atoi(m[2])
	var outs, eps []node.Node
	for _, n := range nodes {
		if _, bad := skipped[n.ID()]; bad {
			continue
		}
		if n.Proto == node.WireGuard {
			eps = append(eps, n)
		} else {
			outs = append(outs, n)
		}
	}
	list := outs
	if m[1] == "endpoint" {
		list = eps
	}
	if idx < len(list) {
		return list[idx].ID()
	}
	return ""
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	return s
}

func contains(a []int, v int) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}

// Close останавливает процесс.
func (l *Lab) Close() {
	l.closeMu.Do(func() {
		if l.proc != nil {
			l.proc.Stop()
		}
	})
}

// Skipped возвращает причину, по которой сервер не попал в ядро.
func (l *Lab) Skipped(id string) error { return l.skipped[id] }

// Has сообщает, загружен ли сервер в ядро.
func (l *Lab) Has(n node.Node) bool { _, ok := l.nodes[n.ID()]; return ok }

// Delay — HTTP-проверка (generate_204) через сервер без использования линий.
func (l *Lab) Delay(ctx context.Context, n node.Node, testURL string, timeout time.Duration) (time.Duration, error) {
	if err := l.skipped[n.ID()]; err != nil {
		return 0, err
	}
	if !l.Has(n) {
		return 0, fmt.Errorf("сервер не загружен в ядро")
	}
	return l.api.Delay(ctx, singbox.Tag(n), testURL, timeout)
}

// WithLane выдаёт свободную линию, направленную через сервер n.
func (l *Lab) WithLane(ctx context.Context, n node.Node, fn func(socksAddr string, c *http.Client) error) error {
	if err := l.skipped[n.ID()]; err != nil {
		return err
	}
	if !l.Has(n) {
		return fmt.Errorf("сервер не загружен в ядро")
	}
	var ln lane
	select {
	case ln = <-l.lanes:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { l.lanes <- ln }()
	if err := l.api.Select(ctx, ln.selector, singbox.Tag(n)); err != nil {
		return err
	}
	return fn("127.0.0.1:"+strconv.Itoa(ln.port), ln.client)
}
