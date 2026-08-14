// Package ssuri реализует разбор ссылок Shadowsocks (ss://) в обоих
// распространённых форматах:
//
//  1. SIP002 (современный):
//     ss://BASE64(method:password)@host:port#tag
//     ss://BASE64(method:password)@host:port?plugin=...#tag
//
//  2. Legacy (старый, целиком в base64):
//     ss://BASE64(method:password@host:port)#tag
package ssuri

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Server описывает один Shadowsocks-сервер.
type Server struct {
	Remarks  string // человекочитаемое имя (tag)
	Method   string // метод шифрования, например aes-256-gcm
	Password string
	Host     string
	Port     int
	Plugin   string // опционально, например obfs-local;obfs=tls
	Raw      string // исходная ss:// строка (для отладки/дедупликации)
}

// ID возвращает строку host:port, используемую для дедупликации.
func (s Server) ID() string {
	return fmt.Sprintf("%s:%d", strings.ToLower(s.Host), s.Port)
}

var ssLineRe = regexp.MustCompile(`ss://[^\s"'<>]+`)

// ExtractAll находит все подстроки вида ss://... в произвольном тексте
// (plain список, base64-blob подписки, YAML и т.д.) и парсит их.
// Ошибочные/повреждённые ссылки молча пропускаются, чтобы одна плохая
// строка не ломала весь список.
func ExtractAll(text string) []Server {
	// Если весь текст выглядит как один base64-blob (подписка), пробуем
	// сначала раскодировать его целиком — тогда внутри появятся строки ss://.
	candidates := []string{text}
	if decoded, ok := tryBase64(strings.TrimSpace(text)); ok {
		candidates = append(candidates, decoded)
	}

	seen := make(map[string]bool)
	var out []Server
	for _, c := range candidates {
		for _, m := range ssLineRe.FindAllString(c, -1) {
			if seen[m] {
				continue
			}
			seen[m] = true
			if srv, err := Parse(m); err == nil {
				out = append(out, srv)
			}
		}
	}
	return out
}

// Parse разбирает одну ss:// ссылку.
func Parse(raw string) (Server, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ss" {
		return Server{}, fmt.Errorf("не похоже на ss:// ссылку: %s", raw)
	}
	remarks := ""
	if u.Fragment != "" {
		if unescaped, err := url.QueryUnescape(u.Fragment); err == nil {
			remarks = unescaped
		} else {
			remarks = u.Fragment
		}
	}

	// SIP002: есть userinfo (before @) и Host отдельно
	if u.User != nil && u.Host != "" {
		userinfo := u.User.String()
		// userinfo обычно base64(method:password), но допускаем и
		// уже декодированный вариант method:password (без паддинга % экранов)
		decodedUser, ok := tryBase64(userinfo)
		if !ok {
			decodedUser = userinfo
		}
		parts := strings.SplitN(decodedUser, ":", 2)
		if len(parts) != 2 {
			return Server{}, fmt.Errorf("не удалось разобрать method:password в %s", raw)
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return Server{}, fmt.Errorf("некорректный порт в %s", raw)
		}
		plugin := ""
		if p := u.Query().Get("plugin"); p != "" {
			if unescaped, err := url.QueryUnescape(p); err == nil {
				plugin = unescaped
			} else {
				plugin = p
			}
		}
		return Server{
			Remarks:  remarks,
			Method:   parts[0],
			Password: parts[1],
			Host:     u.Hostname(),
			Port:     port,
			Plugin:   plugin,
			Raw:      raw,
		}, nil
	}

	// Legacy: ss://BASE64(method:password@host:port)#tag
	// В этом случае net/url кладёт всё в u.Opaque или u.Host пуст.
	body := raw[len("ss://"):]
	if idx := strings.IndexAny(body, "#?"); idx != -1 {
		body = body[:idx]
	}
	decoded, ok := tryBase64(body)
	if !ok {
		return Server{}, fmt.Errorf("не удалось декодировать legacy ss:// ссылку: %s", raw)
	}
	at := strings.LastIndex(decoded, "@")
	colon := strings.Index(decoded, ":")
	if at == -1 || colon == -1 || colon > at {
		return Server{}, fmt.Errorf("некорректный формат внутри legacy ss:// ссылки: %s", raw)
	}
	methodPass := decoded[:at]
	hostPort := decoded[at+1:]
	mp := strings.SplitN(methodPass, ":", 2)
	if len(mp) != 2 {
		return Server{}, fmt.Errorf("не удалось разобрать method:password (legacy): %s", raw)
	}
	hp := strings.SplitN(hostPort, ":", 2)
	if len(hp) != 2 {
		return Server{}, fmt.Errorf("не удалось разобрать host:port (legacy): %s", raw)
	}
	port, err := strconv.Atoi(hp[1])
	if err != nil {
		return Server{}, fmt.Errorf("некорректный порт (legacy): %s", raw)
	}
	return Server{
		Remarks:  remarks,
		Method:   mp[0],
		Password: mp[1],
		Host:     hp[0],
		Port:     port,
		Raw:      raw,
	}, nil
}

// tryBase64 пытается декодировать строку как base64 (в вариантах Std/URL,
// с паддингом и без него — именно так чаще всего портят подписки разные клиенты).
func tryBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	variants := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range variants {
		if b, err := enc.DecodeString(s); err == nil {
			// эвристика: результат должен быть печатным текстом
			if isMostlyPrintable(b) {
				return string(b), true
			}
		}
	}
	return "", false
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) || c >= 0x80 {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.9
}
