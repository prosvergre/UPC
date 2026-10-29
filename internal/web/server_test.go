package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"proxycheck/internal/app"
	"proxycheck/internal/settings"
)

func newTestServer(t *testing.T, password string) (*Server, *httptest.Server) {
	a := app.New(filepath.Join(t.TempDir(), "settings.json"))
	if password != "" {
		h, err := HashPassword(password)
		if err != nil {
			t.Fatal(err)
		}
		a.UpdateSettings(func(s *settings.Settings) { s.WebPasswordHash = h })
	}
	s := New(a)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func do(t *testing.T, c *http.Client, method, url string, body string, hdr map[string]string) *http.Response {
	req, _ := http.NewRequest(method, url, bytes.NewBufferString(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

var xr = map[string]string{"X-Requested-With": "proxycheck", "Content-Type": "application/json"}

func TestNoPasswordLoopbackOpen(t *testing.T) {
	_, ts := newTestServer(t, "")
	if r := do(t, ts.Client(), "GET", ts.URL+"/api/state", "", nil); r.StatusCode != 200 {
		t.Fatalf("state: %d", r.StatusCode)
	}
	if r := do(t, ts.Client(), "GET", ts.URL+"/", "", nil); r.StatusCode != 200 {
		t.Fatalf("index: %d", r.StatusCode)
	}
}

func TestAuthFlowAndCSRF(t *testing.T) {
	_, ts := newTestServer(t, "correct-horse")
	jar := ts.Client()
	jar.Jar, _ = newJar()

	if r := do(t, jar, "GET", ts.URL+"/api/state", "", nil); r.StatusCode != 401 {
		t.Fatalf("без входа должен быть 401, получили %d", r.StatusCode)
	}
	if r := do(t, jar, "POST", ts.URL+"/api/login", `{"password":"wrong"}`, xr); r.StatusCode != 401 {
		t.Fatalf("неверный пароль: %d", r.StatusCode)
	}
	if r := do(t, jar, "POST", ts.URL+"/api/login", `{"password":"correct-horse"}`, map[string]string{"Content-Type": "application/json"}); r.StatusCode != 403 {
		t.Fatalf("логин без X-Requested-With должен быть отклонён: %d", r.StatusCode)
	}
	r := do(t, jar, "POST", ts.URL+"/api/login", `{"password":"correct-horse"}`, xr)
	if r.StatusCode != 200 {
		t.Fatalf("логин: %d", r.StatusCode)
	}
	cookie := ""
	for _, c := range r.Cookies() {
		if c.Name == "pc_session" {
			cookie = c.Value
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Error("cookie должна быть HttpOnly + SameSite=Strict")
			}
		}
	}
	if cookie == "" {
		t.Fatal("нет cookie сессии")
	}
	if r := do(t, jar, "GET", ts.URL+"/api/state", "", nil); r.StatusCode != 200 {
		t.Fatalf("state после входа: %d", r.StatusCode)
	}
	// CSRF: изменяющий запрос без заголовка и с чужим Origin
	if r := do(t, jar, "POST", ts.URL+"/api/cancel", "", nil); r.StatusCode != 403 {
		t.Fatalf("POST без X-Requested-With: %d", r.StatusCode)
	}
	bad := map[string]string{"X-Requested-With": "proxycheck", "Origin": "http://evil.example"}
	if r := do(t, jar, "POST", ts.URL+"/api/cancel", "", bad); r.StatusCode != 403 {
		t.Fatalf("чужой Origin: %d", r.StatusCode)
	}
	if r := do(t, jar, "POST", ts.URL+"/api/cancel", "", xr); r.StatusCode != 200 {
		t.Fatalf("легитимный POST: %d", r.StatusCode)
	}
	// выход
	do(t, jar, "POST", ts.URL+"/api/logout", "", xr)
	if r := do(t, jar, "GET", ts.URL+"/api/state", "", nil); r.StatusCode != 401 {
		t.Fatalf("после выхода: %d", r.StatusCode)
	}
}

func TestLoginRateLimit(t *testing.T) {
	_, ts := newTestServer(t, "correct-horse")
	var last int
	for i := 0; i < 7; i++ {
		last = do(t, ts.Client(), "POST", ts.URL+"/api/login", `{"password":"nope"}`, xr).StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("после серии неудач ожидался 429, получили %d", last)
	}
	// даже верный пароль в окне блокировки не пускает
	if r := do(t, ts.Client(), "POST", ts.URL+"/api/login", `{"password":"correct-horse"}`, xr); r.StatusCode != 429 {
		t.Fatalf("в блокировке: %d", r.StatusCode)
	}
}

func TestNonLoopbackRequiresPassword(t *testing.T) {
	s, _ := newTestServer(t, "")
	if err := s.Check("0.0.0.0:8080"); err == nil {
		t.Fatal("внешний адрес без пароля должен отклоняться")
	}
	if err := s.Check("127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	s2, _ := newTestServer(t, "correct-horse")
	if err := s2.Check("0.0.0.0:8080"); err != nil {
		t.Fatalf("с паролем внешний адрес допустим: %v", err)
	}
	if !IsLoopback("[::1]:80") || IsLoopback("192.168.1.2:80") || strings.Contains("", "x") {
		t.Fatal("IsLoopback")
	}
}

func TestImportAndConfig(t *testing.T) {
	_, ts := newTestServer(t, "")
	text := "ss://YWVzLTI1Ni1nY206ZGVuaTE5ODM=@172.29.37.240:10001#Trixie%20-%20Over%20ZRT\n" +
		"http://Prox:pass@189.110.65.145:3001#MiSina%20HTTP\nvless://not-a-uuid@h.com:443\nмусор\n"
	body := `{"text":` + jsonStr(text) + `,"check":false}`
	r := do(t, ts.Client(), "POST", ts.URL+"/api/import", body, xr)
	if r.StatusCode != 200 {
		t.Fatalf("import: %d", r.StatusCode)
	}
	var res struct {
		Added, Rejected int
		IDs             []string `json:"ids"`
	}
	decode(t, r, &res)
	if res.Added != 2 || len(res.IDs) != 2 || res.Rejected != 1 {
		t.Fatalf("итог импорта: %+v", res)
	}
	// повторная вставка не плодит дубликаты
	r = do(t, ts.Client(), "POST", ts.URL+"/api/import", body, xr)
	var again struct{ Added, Existing int }
	decode(t, r, &again)
	if again.Added != 0 || again.Existing != 2 {
		t.Fatalf("повторный импорт: %+v", again)
	}
	r = do(t, ts.Client(), "GET", ts.URL+"/api/config?id="+res.IDs[0], "", nil)
	var ci struct {
		Link   string
		Fields map[string]string
	}
	decode(t, r, &ci)
	if !strings.HasPrefix(ci.Link, "ss://") || ci.Fields["Адрес"] != "172.29.37.240:10001" || ci.Fields["Шифр/метод"] != "aes-256-gcm" {
		t.Fatalf("config: %+v", ci)
	}
	// удаление
	if r := do(t, ts.Client(), "POST", ts.URL+"/api/delete", `{"id":"`+res.IDs[0]+`"}`, xr); r.StatusCode != 200 {
		t.Fatalf("delete: %d", r.StatusCode)
	}
	if r := do(t, ts.Client(), "GET", ts.URL+"/api/config?id="+res.IDs[0], "", nil); r.StatusCode != 400 {
		t.Fatalf("после удаления конфиг не должен находиться: %d", r.StatusCode)
	}
}
