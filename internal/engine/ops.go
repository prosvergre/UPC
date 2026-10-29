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
	ExitIPURL      = "https://api.ipify.org"
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

// ExitIP определяет выходной IP сервера.
func (l *Lab) ExitIP(ctx context.Context, n node.Node, timeout time.Duration) (string, error) {
	var ip string
	err := l.WithLane(ctx, n, func(_ string, c *http.Client) error {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, _ := http.NewRequestWithContext(cctx, "GET", ExitIPURL, nil)
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		if err != nil {
			return err
		}
		ip = strings.TrimSpace(string(b))
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("сервис вернул не IP: %q", ip)
		}
		return nil
	})
	return ip, err
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
func ExitIPViaSocks(ctx context.Context, socksAddr string, timeout time.Duration) (string, error) {
	proxy, _ := url.Parse("socks5://" + socksAddr)
	c := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	req, _ := http.NewRequestWithContext(ctx, "GET", ExitIPURL, nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("сервис вернул не IP: %q", ip)
	}
	return ip, nil
}
