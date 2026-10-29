package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"proxycheck/internal/node"
	"proxycheck/internal/speedtest"
)

// Адреса проверки. generate_204 — стандарт для url-test; запрос идёт через
// сервер по HTTPS-цепочке ядра, поэтому подтверждает, что трафик реально проходит.
const (
	DefaultTestURL = "https://www.gstatic.com/generate_204"
)

// Result — результат проверки одного сервера.
type Result struct {
	Node    node.Node
	Alive   bool
	Latency time.Duration
	Err     error
}

// Progress вызывается после каждой проверки (под мьютексом, последовательно).
type Progress func(done, total int, r Result)

// CheckAll проверяет серверы параллельно (concurrency запросов к одному ядру).
// Порядок результатов совпадает с порядком входа.
func (l *Lab) CheckAll(ctx context.Context, nodes []node.Node, concurrency int, timeout time.Duration, onProgress Progress) []Result {
	if concurrency <= 0 {
		concurrency = 32
	}
	res := make([]Result, len(nodes))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				d, err := l.Delay(ctx, nodes[i], l.checkURL(), timeout)
				r := Result{Node: nodes[i], Alive: err == nil, Latency: d, Err: err}
				res[i] = r
				mu.Lock()
				done++
				if onProgress != nil {
					onProgress(done, len(nodes), r)
				}
				mu.Unlock()
			}
		}()
	}
loop:
	for i := range nodes {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break loop
		}
	}
	close(jobs)
	wg.Wait()
	for i := range res {
		if res[i].Node.Host == "" { // не дошли из-за отмены
			res[i] = Result{Node: nodes[i], Err: ctx.Err()}
		}
	}
	return res
}

// exitIPSources — сервисы определения IP; пробуем по очереди: часть серверов
// режет отдельные домены, поэтому один сервис не показатель.
var exitIPSources = []string{
	"https://api.ipify.org",
	"https://icanhazip.com",
	"https://ifconfig.me/ip",
	"https://www.cloudflare.com/cdn-cgi/trace",
}

// parseIPBody достаёт IP из ответа сервиса (простой текст или cdn-cgi/trace).
func parseIPBody(b []byte) string {
	txt := strings.TrimSpace(string(b))
	for _, line := range strings.Split(txt, "\n") {
		if strings.HasPrefix(line, "ip=") {
			txt = strings.TrimSpace(strings.TrimPrefix(line, "ip="))
			break
		}
	}
	if net.ParseIP(txt) == nil {
		return ""
	}
	return txt
}

// ExitIP определяет выходной IP сервера. perTry — таймаут на один сервис;
// при неудаче пробуются остальные, в ошибке перечислены причины всех попыток.
func (l *Lab) ExitIP(ctx context.Context, n node.Node, perTry time.Duration) (string, error) {
	var ip string
	err := l.WithLane(ctx, n, func(_ string, c *http.Client) error {
		var errs []string
		for _, u := range exitIPSources {
			if ctx.Err() != nil {
				break
			}
			got, err := fetchIP(ctx, c, u, perTry)
			if err == nil {
				ip = got
				return nil
			}
			errs = append(errs, fmt.Sprintf("%s: %v", strings.TrimPrefix(u, "https://"), err))
		}
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	})
	return ip, err
}

func fetchIP(ctx context.Context, c *http.Client, u string, timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(cctx, "GET", u, nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", shortErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if err != nil {
		return "", shortErr(err)
	}
	ip := parseIPBody(b)
	if ip == "" {
		return "", fmt.Errorf("ответ не содержит IP")
	}
	return ip, nil
}

func shortErr(err error) error {
	m := err.Error()
	if i := strings.LastIndex(m, ": "); i >= 0 && len(m) > 80 {
		m = m[i+2:]
	}
	return fmt.Errorf("%s", m)
}

// Speed измеряет скорость скачивания и (если upload) отдачи через сервер.
func (l *Lab) Speed(ctx context.Context, n node.Node, upload bool, timeout time.Duration) (down speedtest.Result, up speedtest.Result, downErr, upErr error) {
	err := l.WithLane(ctx, n, func(addr string, _ *http.Client) error {
		down, downErr = speedtest.Download(addr, "", timeout)
		if upload {
			up, upErr = speedtest.Upload(addr, "", 0, timeout)
		}
		return nil
	})
	if err != nil {
		downErr = err
		if upload {
			upErr = err
		}
	}
	return
}

func (l *Lab) checkURL() string {
	if l.CheckURL != "" {
		return l.CheckURL
	}
	return DefaultTestURL
}

// ExitIPViaSocks определяет выходной IP через уже работающий локальный
// SOCKS5-вход (например, активную линию), не поднимая отдельного ядра.
func ExitIPViaSocks(ctx context.Context, socksAddr string, perTry time.Duration) (string, error) {
	proxy, _ := url.Parse("socks5://" + socksAddr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	var errs []string
	for _, u := range exitIPSources {
		ip, err := fetchIP(ctx, c, u, perTry)
		if err == nil {
			return ip, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", strings.TrimPrefix(u, "https://"), err))
	}
	return "", fmt.Errorf("%s", strings.Join(errs, "; "))
}
