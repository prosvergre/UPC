package node

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ssMethods — шифры, которые умеет sing-box (shadowsocks outbound).
var ssMethods = map[string]bool{
	"none": true, "aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"rc4-md5": true, "chacha20-ietf": true, "xchacha20": true,
}

// Validate быстро отсеивает серверы, на которых ядро заведомо не стартует
// (один плохой outbound ломает запуск всего конфига, поэтому проверяем заранее).
func Validate(n Node) error {
	if strings.TrimSpace(n.Host) == "" || n.Port <= 0 || n.Port > 65535 {
		return fmt.Errorf("некорректный адрес")
	}
	switch n.Proto {
	case SS:
		if !ssMethods[n.Method] {
			return fmt.Errorf("ss: неизвестный метод %q", n.Method)
		}
		if strings.HasPrefix(n.Method, "2022-") {
			if err := checkKey(n.Password, 0, true); err != nil {
				return fmt.Errorf("ss2022: ключ: %w", err)
			}
		}
	case VLESS, VMess:
		if n.Proto == VLESS && n.Flow != "" && n.Flow != "xtls-rprx-vision" {
			return fmt.Errorf("vless: неподдерживаемый flow %q", n.Flow)
		}
		if !uuidRe.MatchString(n.UUID) {
			return fmt.Errorf("%s: некорректный uuid", n.Proto)
		}
	case TUIC:
		if !uuidRe.MatchString(n.UUID) {
			return fmt.Errorf("tuic: некорректный uuid")
		}
	}
	if n.Security == "reality" {
		if err := checkKey(n.PublicKey, 32, false); err != nil {
			return fmt.Errorf("reality public key: %w", err)
		}
		if len(n.ShortID) > 16 || len(n.ShortID)%2 != 0 || !isHex(n.ShortID) {
			return fmt.Errorf("reality short id")
		}
	}
	if n.Proto == WireGuard {
		for _, k := range []string{"private_key", "public_key"} {
			if err := checkKey(n.Extra[k], 32, false); err != nil {
				return fmt.Errorf("wireguard %s: %w", k, err)
			}
		}
	}
	return nil
}

// checkKey проверяет base64-ключ; want==0 — длина не проверяется
// (для ss2022 допустимы 16 или 32 байта в зависимости от метода).
func checkKey(s string, want int, ss2022 bool) error {
	if s == "" {
		return fmt.Errorf("пусто")
	}
	var b []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err = enc.DecodeString(s); err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("не base64")
	}
	if ss2022 {
		if len(b) != 16 && len(b) != 32 {
			return fmt.Errorf("длина %d байт", len(b))
		}
		return nil
	}
	if want > 0 && len(b) != want {
		return fmt.Errorf("длина %d байт, нужно %d", len(b), want)
	}
	return nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
