package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// API — клиент Clash API sing-box.
type API struct {
	Addr   string // host:port
	Secret string
	HTTP   *http.Client
}

func (a *API) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (a *API) do(ctx context.Context, method, path string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://"+a.Addr+path, body)
	if err != nil {
		return nil, 0, err
	}
	if a.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+a.Secret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return b, resp.StatusCode, err
}

// Delay измеряет задержку до testURL через outbound с тегом tag (без входов и портов).
func (a *API) Delay(ctx context.Context, tag, testURL string, timeout time.Duration) (time.Duration, error) {
	q := url.Values{"url": {testURL}, "timeout": {fmt.Sprint(timeout.Milliseconds())}}
	b, code, err := a.do(ctx, "GET", "/proxies/"+url.PathEscape(tag)+"/delay?"+q.Encode(), nil)
	if err != nil {
		return 0, err
	}
	if code != 200 {
		return 0, fmt.Errorf("delay %s: HTTP %d: %s", tag, code, strings.TrimSpace(string(b)))
	}
	var r struct {
		Delay int `json:"delay"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return 0, err
	}
	return time.Duration(r.Delay) * time.Millisecond, nil
}

// Select переключает selector на outbound без перезапуска процесса.
func (a *API) Select(ctx context.Context, selector, outbound string) error {
	body, _ := json.Marshal(map[string]string{"name": outbound})
	b, code, err := a.do(ctx, "PUT", "/proxies/"+url.PathEscape(selector), strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	if code != 204 && code != 200 {
		return fmt.Errorf("select %s→%s: HTTP %d: %s", selector, outbound, code, strings.TrimSpace(string(b)))
	}
	return nil
}

// Conn — активное соединение из /connections.
type Conn struct {
	ID       string `json:"id"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Metadata struct {
		InboundPort string `json:"inboundPort"`
		InboundName string `json:"inbound"`
	} `json:"metadata"`
	Chains []string `json:"chains"`
}

// Connections возвращает активные соединения и суммарный трафик ядра.
func (a *API) Connections(ctx context.Context) (conns []Conn, upTotal, downTotal int64, err error) {
	b, code, err := a.do(ctx, "GET", "/connections", nil)
	if err != nil {
		return nil, 0, 0, err
	}
	if code != 200 {
		return nil, 0, 0, fmt.Errorf("connections: HTTP %d", code)
	}
	var r struct {
		Up    int64  `json:"uploadTotal"`
		Down  int64  `json:"downloadTotal"`
		Conns []Conn `json:"connections"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, 0, 0, err
	}
	return r.Conns, r.Up, r.Down, nil
}
