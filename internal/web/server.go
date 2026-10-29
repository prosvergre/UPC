// Package web — HTTP-интерфейс к ядру приложения (internal/app): JSON API и
// вшитая страница. Без пароля слушает только loopback; для любого другого
// адреса пароль обязателен (проверяется при запуске).
package web

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"proxycheck/internal/app"
)

//go:embed static/index.html
var static embed.FS

// Server — веб-сервер.
type Server struct {
	App *app.App

	mu       sync.Mutex
	sessions map[string]time.Time
	fails    map[string]*failState
	secure   bool // выставлять Secure у cookie (при TLS)
}

type failState struct {
	n     int
	until time.Time
}

// New создаёт сервер.
func New(a *app.App) *Server {
	return &Server{App: a, sessions: map[string]time.Time{}, fails: map[string]*failState{}}
}

// HashPassword возвращает bcrypt-хеш для хранения в настройках.
func HashPassword(p string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return string(b), err
}

// IsLoopback сообщает, что адрес слушателя доступен только локально.
func IsLoopback(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Check проверяет допустимость адреса: не-loopback без пароля запрещён.
func (s *Server) Check(addr string) error {
	if !IsLoopback(addr) && s.App.Settings().WebPasswordHash == "" {
		return fmt.Errorf("адрес %s доступен извне: сначала задайте пароль (-set-web-password)", addr)
	}
	return nil
}

// ListenAndServe запускает сервер (с TLS, если заданы certFile и keyFile).
func (s *Server) ListenAndServe(addr, certFile, keyFile string) error {
	if err := s.Check(addr); err != nil {
		return err
	}
	srv := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if certFile != "" && keyFile != "" {
		s.secure = true
		return srv.ListenAndServeTLS(certFile, keyFile)
	}
	return srv.ListenAndServe()
}

// Handler возвращает корневой обработчик (удобно для тестов).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", s.handleAuth)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.guard(s.handleLogout))
	mux.HandleFunc("/api/state", s.guard(s.handleState))
	mux.HandleFunc("/api/scan", s.guard(post(func(w http.ResponseWriter, r *http.Request) { s.run(w, s.App.Scan()) })))
	mux.HandleFunc("/api/recheck", s.guard(post(func(w http.ResponseWriter, r *http.Request) { s.run(w, s.App.Recheck()) })))
	mux.HandleFunc("/api/cancel", s.guard(post(func(w http.ResponseWriter, r *http.Request) { s.App.Cancel(); s.run(w, nil) })))
	mux.HandleFunc("/api/select", s.guard(post(s.handleSelect)))
	mux.HandleFunc("/api/line", s.guard(s.handleLine))
	mux.HandleFunc("/api/speed", s.guard(post(s.handleSpeed)))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, _ := static.ReadFile("static/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Write(b)
	})
	return mux
}

func (s *Server) authRequired() bool { return s.App.Settings().WebPasswordHash != "" }

func (s *Server) authed(r *http.Request) bool {
	if !s.authRequired() {
		return true
	}
	c, err := r.Cookie("pc_session")
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(s.sessions, c.Value)
		return false
	}
	return true
}

// guard требует вход и защищает изменяющие запросы от CSRF.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			http.Error(w, `{"error":"требуется вход"}`, http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && !sameOrigin(r) {
			http.Error(w, `{"error":"чужой источник запроса"}`, http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// sameOrigin: у изменяющих запросов Origin (если есть) должен совпадать с Host,
// а заголовок X-Requested-With блокирует простые кросс-сайтовые формы.
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("X-Requested-With") != "proxycheck" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host != r.Host {
			return false
		}
	}
	return true
}

func post(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"нужен POST"}`, http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) run(w http.ResponseWriter, err error) {
	if err != nil {
		code := http.StatusBadRequest
		if err == app.ErrBusy {
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.App.Snapshot())
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]bool{"required": s.authRequired(), "authenticated": s.authed(r)})
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !sameOrigin(r) {
		http.Error(w, `{"error":"недопустимый запрос"}`, http.StatusForbidden)
		return
	}
	ip := clientIP(r)
	s.mu.Lock()
	f := s.fails[ip]
	if f != nil && time.Now().Before(f.until) {
		s.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "слишком много попыток, подождите минуту"})
		return
	}
	s.mu.Unlock()

	var body struct {
		Password string `json:"password"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	hash := s.App.Settings().WebPasswordHash
	ok := hash != "" && bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) == nil
	if !ok {
		s.mu.Lock()
		if s.fails[ip] == nil {
			s.fails[ip] = &failState{}
		}
		s.fails[ip].n++
		if s.fails[ip].n >= 5 {
			s.fails[ip].until = time.Now().Add(time.Minute)
			s.fails[ip].n = 0
		}
		s.mu.Unlock()
		time.Sleep(500 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "неверный пароль"})
		return
	}
	b := make([]byte, 24)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	delete(s.fails, ip)
	s.sessions[tok] = time.Now().Add(12 * time.Hour)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "pc_session", Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.secure, MaxAge: 12 * 3600})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("pc_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "pc_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleSelect(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
		On bool   `json:"on"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b) != nil || b.ID == "" {
		s.run(w, fmt.Errorf("некорректный запрос"))
		return
	}
	s.App.Select(b.ID, b.On)
	s.run(w, nil)
}

func (s *Server) handleLine(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var b struct {
			ID   string `json:"id"`
			Port int    `json:"port"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b) != nil || b.ID == "" {
			s.run(w, fmt.Errorf("некорректный запрос"))
			return
		}
		port, err := s.App.StartLine(b.ID, b.Port)
		if err != nil {
			s.run(w, err)
			return
		}
		writeJSON(w, 200, map[string]int{"port": port})
	case http.MethodDelete:
		s.run(w, s.App.StopLine(strings.TrimSpace(r.URL.Query().Get("id"))))
	default:
		http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSpeed(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IDs []string `json:"ids"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&b) != nil {
		s.run(w, fmt.Errorf("некорректный запрос"))
		return
	}
	s.run(w, s.App.SpeedTest(b.IDs))
}
