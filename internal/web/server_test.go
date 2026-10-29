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

func TestManualAndSubscriptions(t *testing.T) {
	_, ts := newTestServer(t, "")
	c := ts.Client()
	// ручной ввод vless+reality (как отправляет форма)
	pk := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	body := `{"proto":"vless","name":"мой","host":"1.2.3.4","port":443,"uuid":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision","network":"","security":"reality","sni":"www.microsoft.com","fingerprint":"chrome","public_key":"` + pk + `","short_id":"ab12","alpn":[],"extra":{}}`
	r := do(t, c, "POST", ts.URL+"/api/manual", body, xr)
	if r.StatusCode != 200 {
		t.Fatalf("manual: %d", r.StatusCode)
	}
	var m struct{ ID string }
	decode(t, r, &m)
	r = do(t, c, "GET", ts.URL+"/api/config?id="+m.ID, "", nil)
	var ci struct {
		Link   string
		Fields map[string]string
	}
	decode(t, r, &ci)
	if !strings.HasPrefix(ci.Link, "vless://11111111") || ci.Fields["Безопасность"] != "reality" {
		t.Fatalf("ссылка из формы: %+v", ci)
	}
	// некорректный uuid отклоняется с понятной ошибкой
	bad := strings.Replace(body, "11111111-2222-3333-4444-555555555555", "oops", 1)
	if r := do(t, c, "POST", ts.URL+"/api/manual", bad, xr); r.StatusCode != 400 {
		t.Fatalf("плохой uuid: %d", r.StatusCode)
	}
	// ручной ss
	ss := `{"proto":"ss","name":"s","host":"5.5.5.5","port":8388,"method":"aes-256-gcm","password":"pw","extra":{}}`
	if r := do(t, c, "POST", ts.URL+"/api/manual", ss, xr); r.StatusCode != 200 {
		t.Fatalf("ss manual: %d", r.StatusCode)
	}

	// подписки: по умолчанию подставляется встроенный список; сохранение и валидация
	r = do(t, c, "GET", ts.URL+"/api/settings", "", nil)
	var st struct {
		Subscriptions []struct {
			URL     string `json:"url"`
			Enabled bool   `json:"enabled"`
		} `json:"subscriptions"`
	}
	decode(t, r, &st)
	if len(st.Subscriptions) < 3 {
		t.Fatalf("встроенные источники не подставились: %d", len(st.Subscriptions))
	}
	if r := do(t, c, "POST", ts.URL+"/api/subs", `{"subscriptions":[{"url":"ftp://x/y","name":"x","enabled":true}]}`, xr); r.StatusCode != 400 {
		t.Fatalf("ftp-ссылка должна отклоняться: %d", r.StatusCode)
	}
	good := `{"subscriptions":[{"url":"https://example.com/sub.txt","name":"","enabled":true,"max_age_days":14},{"url":"https://example.com/sub.txt","name":"dup","enabled":true}]}`
	if r := do(t, c, "POST", ts.URL+"/api/subs", good, xr); r.StatusCode != 200 {
		t.Fatalf("subs: %d", r.StatusCode)
	}
	r = do(t, c, "GET", ts.URL+"/api/settings", "", nil)
	var st2 struct {
		Subscriptions []struct{ URL, Name string }
	}
	decode(t, r, &st2)
	if len(st2.Subscriptions) != 1 || st2.Subscriptions[0].Name == "" {
		t.Fatalf("дубликат не схлопнулся / имя не подставилось: %+v", st2)
	}
	// автопроверка: минимум 5 минут
	if r := do(t, c, "POST", ts.URL+"/api/auto", `{"scan_min":1}`, xr); r.StatusCode != 400 {
		t.Fatalf("scan_min=1: %d", r.StatusCode)
	}
	if r := do(t, c, "POST", ts.URL+"/api/auto", `{"scan_min":30,"scan_on_start":true}`, xr); r.StatusCode != 200 {
		t.Fatalf("auto: %d", r.StatusCode)
	}
	// флаг отдаётся, мусорное имя — нет
	if r := do(t, c, "GET", ts.URL+"/flags/gb.svg", "", nil); r.StatusCode != 200 || r.Header.Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("flag: %d", r.StatusCode)
	}
	if r := do(t, c, "GET", ts.URL+"/flags/../x.svg", "", nil); r.StatusCode == 200 {
		t.Fatal("path traversal")
	}
}

func TestManualExtrasAndEdit(t *testing.T) {
	_, ts := newTestServer(t, "")
	c := ts.Client()
	body := `{"proto":"ss","name":"s","host":"5.5.5.5","port":8388,"method":"aes-256-gcm","password":"pw","extra":{"uot":"1","mux":"smux","outbound_json":"{\"tcp_fast_open\":true}"}}`
	r := do(t, c, "POST", ts.URL+"/api/manual", body, xr)
	if r.StatusCode != 200 {
		t.Fatalf("manual: %d", r.StatusCode)
	}
	var m struct{ ID string }
	decode(t, r, &m)
	r = do(t, c, "GET", ts.URL+"/api/config?id="+m.ID, "", nil)
	var ci struct {
		Node struct {
			Extra map[string]string `json:"extra"`
		} `json:"node"`
	}
	decode(t, r, &ci)
	if ci.Node.Extra["uot"] != "1" || ci.Node.Extra["mux"] != "smux" {
		t.Fatalf("extras потерялись: %+v", ci.Node.Extra)
	}
	// редактирование: старый заменяется, extras обновляются
	edit := `{"replace_id":"` + m.ID + `","proto":"ss","name":"s2","host":"5.5.5.5","port":8388,"method":"aes-256-gcm","password":"pw","extra":{"mux":"yamux"}}`
	r = do(t, c, "POST", ts.URL+"/api/manual", edit, xr)
	if r.StatusCode != 200 {
		t.Fatalf("edit: %d", r.StatusCode)
	}
	var m2 struct{ ID string }
	decode(t, r, &m2)
	r = do(t, c, "GET", ts.URL+"/api/state", "", nil)
	var st struct{ Rows []struct{ ID, Name string } }
	decode(t, r, &st)
	if len(st.Rows) != 1 || st.Rows[0].Name != "s2" {
		t.Fatalf("после редактирования должна остаться одна строка s2: %+v", st.Rows)
	}
	// кривой JSON в доп. настройках отклоняется
	badj := `{"proto":"ss","name":"s","host":"6.6.6.6","port":8388,"method":"aes-256-gcm","password":"pw","extra":{"outbound_json":"{oops"}}`
	if r := do(t, c, "POST", ts.URL+"/api/manual", badj, xr); r.StatusCode != 400 {
		t.Fatalf("плохой JSON: %d", r.StatusCode)
	}
}
