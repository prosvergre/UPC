package node

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var schemeRe = regexp.MustCompile(`(?i)\b(?:ss|vless|vmess|trojan|socks|socks4|socks4a|socks5|socks5h|hysteria|hysteria2|hy2|tuic|wireguard|wg|ssh)://[^\s"'<>\x60,]+`)
var httpLineRe = regexp.MustCompile(`(?i)^(?:https?)://[^\s/"'<>]+:\d{1,5}/?$`)

// ExtractAll находит и разбирает все ссылки в произвольном тексте: список по
// строкам, base64-подписка целиком, смесь. Битые ссылки молча пропускаются.
// http(s):// считается прокси только если это отдельная строка вида
// http://host:port (иначе в подписках ловились бы обычные веб-ссылки).
func ExtractAll(text string) []Node {
	cands := []string{text}
	if d, ok := tryBase64(strings.TrimSpace(text)); ok {
		cands = append(cands, d)
	}
	seen := map[string]bool{}
	var out []Node
	add := func(raw string) {
		if seen[raw] {
			return
		}
		seen[raw] = true
		if n, err := Parse(raw); err == nil {
			out = append(out, n)
		}
	}
	for _, c := range cands {
		for _, m := range schemeRe.FindAllString(c, -1) {
			add(m)
		}
		for _, line := range strings.Split(c, "\n") {
			line = strings.TrimSpace(line)
			if httpLineRe.MatchString(line) {
				add(line)
			}
		}
	}
	return out
}

// Parse разбирает одну ссылку.
func Parse(raw string) (Node, error) {
	raw = strings.TrimSpace(raw)
	i := strings.Index(raw, "://")
	if i <= 0 {
		return Node{}, fmt.Errorf("нет схемы: %q", raw)
	}
	scheme := strings.ToLower(raw[:i])
	var n Node
	var err error
	switch scheme {
	case "ss":
		n, err = parseSS(raw)
	case "vmess":
		n, err = parseVMess(raw)
	case "vless":
		n, err = parseURLProto(raw, VLESS)
	case "trojan":
		n, err = parseURLProto(raw, Trojan)
	case "socks", "socks5", "socks5h":
		n, err = parseURLProto(raw, Socks)
		n.Version = 5
	case "socks4", "socks4a":
		n, err = parseURLProto(raw, Socks)
		n.Version = 4
	case "http", "https":
		n, err = parseURLProto(raw, HTTP)
		if scheme == "https" {
			n.Security = "tls"
		}
	case "hysteria":
		n, err = parseURLProto(raw, Hysteria)
	case "hysteria2", "hy2":
		n, err = parseURLProto(raw, Hysteria2)
	case "tuic":
		n, err = parseURLProto(raw, TUIC)
	case "wireguard", "wg":
		n, err = parseURLProto(raw, WireGuard)
	case "ssh":
		n, err = parseURLProto(raw, SSH)
	default:
		return Node{}, fmt.Errorf("неизвестная схема %q", scheme)
	}
	if err != nil {
		return Node{}, err
	}
	if n.Host == "" || n.Port <= 0 || n.Port > 65535 {
		return Node{}, fmt.Errorf("некорректный адрес: %q", raw)
	}
	n.Raw = raw
	return n, nil
}

// ---------- общий разбор URL-подобных схем ----------

func parseURLProto(raw string, proto string) (Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Node{}, err
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Node{}, fmt.Errorf("порт: %w", err)
	}
	q := u.Query()
	n := Node{Proto: proto, Host: u.Hostname(), Port: port, Name: u.Fragment}
	user := ""
	pass := ""
	hasPass := false
	if u.User != nil {
		user = u.User.Username()
		pass, hasPass = u.User.Password()
	}

	switch proto {
	case VLESS:
		n.UUID = user
		n.Flow = q.Get("flow")
		readTransport(&n, q)
		readTLS(&n, q, false)
	case Trojan:
		n.Password = user
		if hasPass {
			n.Password = user + ":" + pass
		}
		readTransport(&n, q)
		readTLS(&n, q, true)
	case Socks, HTTP:
		n.Username, n.Password = user, pass
	case SSH:
		n.Username, n.Password = user, pass
		n.extra("private_key", q.Get("private_key"))
		n.extra("private_key_passphrase", q.Get("private_key_passphrase"))
		n.extra("host_key", q.Get("host_key"))
	case Hysteria2:
		n.Password = user
		if hasPass {
			n.Password = user + ":" + pass
		}
		readTLS(&n, q, true)
		n.extra("obfs", q.Get("obfs"))
		n.extra("obfs_password", firstNonEmpty(q.Get("obfs-password"), q.Get("obfs_password")))
		n.extra("pin_sha256", q.Get("pinSHA256"))
		n.extra("up_mbps", q.Get("upmbps"))
		n.extra("down_mbps", q.Get("downmbps"))
	case Hysteria:
		n.Password = firstNonEmpty(q.Get("auth"), q.Get("auth_str"), user)
		readTLS(&n, q, true)
		if n.SNI == "" {
			n.SNI = q.Get("peer")
		}
		n.extra("obfs", firstNonEmpty(q.Get("obfsParam"), q.Get("obfs")))
		n.extra("up_mbps", firstNonEmpty(q.Get("upmbps"), q.Get("up")))
		n.extra("down_mbps", firstNonEmpty(q.Get("downmbps"), q.Get("down")))
	case TUIC:
		n.UUID, n.Password = user, pass
		readTLS(&n, q, true)
		n.extra("congestion_control", q.Get("congestion_control"))
		n.extra("udp_relay_mode", q.Get("udp_relay_mode"))
		if q.Get("allow_insecure") == "1" || q.Get("allow_insecure") == "true" {
			n.Insecure = true
		}
	case WireGuard:
		n.extra("private_key", user)
		n.extra("public_key", firstNonEmpty(q.Get("publickey"), q.Get("public_key"), q.Get("peer_public_key")))
		n.extra("pre_shared_key", firstNonEmpty(q.Get("presharedkey"), q.Get("pre_shared_key")))
		n.extra("address", firstNonEmpty(q.Get("address"), q.Get("ip")))
		n.extra("reserved", q.Get("reserved"))
		n.extra("mtu", q.Get("mtu"))
		if n.Extra["private_key"] == "" || n.Extra["public_key"] == "" {
			return Node{}, fmt.Errorf("wireguard: нужны private и public ключи")
		}
	}
	if n.Name == "" {
		n.Name = q.Get("remarks")
	}
	return n, nil
}

func readTransport(n *Node, q url.Values) {
	t := firstNonEmpty(q.Get("type"), q.Get("network"))
	switch t {
	case "", "tcp", "raw":
		n.Network = ""
	case "h2", "http":
		n.Network = "http"
	default:
		n.Network = t // ws, grpc, httpupgrade
	}
	n.Path = q.Get("path")
	n.HostHeader = q.Get("host")
	n.ServiceName = firstNonEmpty(q.Get("serviceName"), q.Get("service_name"))
	if n.Network == "grpc" && n.ServiceName == "" {
		n.ServiceName = n.Path
	}
}

func readTLS(n *Node, q url.Values, tlsDefault bool) {
	sec := q.Get("security")
	if sec == "" && tlsDefault {
		sec = "tls"
	}
	if sec == "none" {
		sec = ""
	}
	n.Security = sec
	n.SNI = firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("servername"))
	if a := q.Get("alpn"); a != "" {
		n.ALPN = strings.Split(a, ",")
	}
	n.Fingerprint = firstNonEmpty(q.Get("fp"), q.Get("fingerprint"))
	if v := firstNonEmpty(q.Get("insecure"), q.Get("allowInsecure"), q.Get("allow_insecure")); v == "1" || v == "true" {
		n.Insecure = true
	}
	n.PublicKey = q.Get("pbk")
	n.ShortID = q.Get("sid")
}

// ---------- Shadowsocks ----------

func parseSS(raw string) (Node, error) {
	body := raw[len("ss://"):]
	name := ""
	if i := strings.Index(body, "#"); i >= 0 {
		name = unescape(body[i+1:])
		body = body[:i]
	}
	query := ""
	if i := strings.Index(body, "?"); i >= 0 {
		query = body[i+1:]
		body = body[:i]
	}
	body = strings.TrimSuffix(body, "/")
	n := Node{Proto: SS, Name: name}

	var userinfo, hostport string
	if at := strings.LastIndex(body, "@"); at >= 0 {
		userinfo, hostport = body[:at], body[at+1:]
		// SIP002: base64url(method:password); SIP022 и др. — method:password в процентном кодировании.
		if d, ok := tryBase64(userinfo); ok && strings.Contains(d, ":") {
			userinfo = d
		} else {
			userinfo = unescape(userinfo)
		}
	} else {
		// legacy: base64(method:password@host:port)
		d, ok := tryBase64(body)
		if !ok {
			return Node{}, fmt.Errorf("ss: не удалось декодировать")
		}
		at := strings.LastIndex(d, "@")
		if at < 0 {
			return Node{}, fmt.Errorf("ss: нет @ в legacy-ссылке")
		}
		userinfo, hostport = d[:at], d[at+1:]
	}
	mp := strings.SplitN(userinfo, ":", 2)
	if len(mp) != 2 || mp[0] == "" {
		return Node{}, fmt.Errorf("ss: не разобрать method:password")
	}
	n.Method, n.Password = strings.ToLower(mp[0]), mp[1]
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return Node{}, fmt.Errorf("ss: адрес: %w", err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return Node{}, fmt.Errorf("ss: порт: %w", err)
	}
	n.Host, n.Port = h, port
	if query != "" {
		if q, err := url.ParseQuery(query); err == nil {
			n.Plugin = q.Get("plugin")
		}
	}
	return n, nil
}

// ---------- VMess ----------

type vmessJSON struct {
	PS   string      `json:"ps"`
	Add  string      `json:"add"`
	Port interface{} `json:"port"`
	ID   string      `json:"id"`
	Aid  interface{} `json:"aid"`
	Scy  string      `json:"scy"`
	Net  string      `json:"net"`
	Type string      `json:"type"`
	Host string      `json:"host"`
	Path string      `json:"path"`
	TLS  string      `json:"tls"`
	SNI  string      `json:"sni"`
	ALPN string      `json:"alpn"`
	FP   string      `json:"fp"`
}

func parseVMess(raw string) (Node, error) {
	body := raw[len("vmess://"):]
	if i := strings.Index(body, "#"); i >= 0 {
		body = body[:i]
	}
	d, ok := tryBase64(body)
	if !ok || !strings.HasPrefix(strings.TrimSpace(d), "{") {
		// редкий URL-вид vmess://uuid@host:port?...
		return parseURLProto2(raw)
	}
	var j vmessJSON
	if err := json.Unmarshal([]byte(d), &j); err != nil {
		return Node{}, fmt.Errorf("vmess json: %w", err)
	}
	n := Node{Proto: VMess, Name: j.PS, Host: j.Add, Port: toInt(j.Port), UUID: j.ID, AlterID: toInt(j.Aid),
		Method: j.Scy, Path: j.Path, HostHeader: j.Host, SNI: j.SNI, Fingerprint: j.FP}
	if n.Method == "" {
		n.Method = "auto"
	}
	switch j.Net {
	case "", "tcp":
		if j.Type == "http" { // tcp+http-обфускация не поддержана ядром как есть
			n.Network = "http"
		}
	case "h2":
		n.Network = "http"
	case "grpc":
		n.Network = "grpc"
		n.ServiceName = j.Path
	default:
		n.Network = j.Net
	}
	if j.TLS == "tls" {
		n.Security = "tls"
	}
	if j.ALPN != "" {
		n.ALPN = strings.Split(j.ALPN, ",")
	}
	return n, nil
}

func parseURLProto2(raw string) (Node, error) {
	n, err := parseURLProto(raw, VMess)
	if err != nil {
		return n, err
	}
	n.UUID, n.Method = n.Username, "auto"
	if u, e := url.Parse(raw); e == nil && u.User != nil {
		n.UUID = u.User.Username()
	}
	n.Username = ""
	return n, nil
}

// ---------- утилиты ----------

func toInt(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(x))
		return i
	}
	return 0
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func unescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

func tryBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && mostlyPrintable(b) {
			return string(b), true
		}
	}
	return "", false
}

func mostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	ok := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) || c >= 0x80 {
			ok++
		}
	}
	return float64(ok)/float64(len(b)) > 0.9
}
