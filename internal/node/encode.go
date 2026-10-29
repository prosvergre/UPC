package node

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// Summary — короткое описание параметров для колонки таблицы:
// у ss это шифр, у vless/vmess/trojan — транспорт, безопасность и flow и т.д.
func (n Node) Summary() string {
	var p []string
	add := func(s string) {
		if s != "" {
			p = append(p, s)
		}
	}
	switch n.Proto {
	case SS:
		add(n.Method)
		if n.Plugin != "" {
			name, _, _ := strings.Cut(n.Plugin, ";")
			add("plugin:" + name)
		}
	case VLESS, VMess, Trojan:
		if n.Network == "" {
			add("tcp")
		} else {
			add(n.Network)
		}
		add(n.Security)
		add(n.Flow)
		if n.Proto == VMess && n.Method != "" && n.Method != "auto" {
			add(n.Method)
		}
	case Socks:
		add("v" + strconv.Itoa(map[bool]int{true: n.Version, false: 5}[n.Version != 0]))
		if n.Username != "" {
			add("auth")
		}
	case HTTP:
		add(map[bool]string{true: "https", false: "http"}[n.Security == "tls"])
		if n.Username != "" {
			add("auth")
		}
	case Hysteria, Hysteria2:
		if o := n.Extra["obfs"]; o != "" {
			add("obfs:" + o)
		}
		add(n.Security)
	case TUIC:
		add(n.Extra["congestion_control"])
		add(n.Extra["udp_relay_mode"])
	case WireGuard:
		add("udp")
	case SSH:
		if n.Extra["private_key"] != "" {
			add("key")
		} else {
			add("password")
		}
	}
	return strings.Join(p, " · ")
}

func q(v url.Values, k, val string) {
	if val != "" {
		v.Set(k, val)
	}
}

// Encode собирает ссылку из полей сервера (для серверов, введённых вручную).
// Parse(Encode(n)) возвращает сервер с тем же ID.
func Encode(n Node) string {
	host := n.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	hp := host + ":" + strconv.Itoa(n.Port)
	frag := ""
	if n.Name != "" {
		frag = "#" + url.PathEscape(n.Name)
	}
	v := url.Values{}
	tls := func() {
		q(v, "security", n.Security)
		q(v, "sni", n.SNI)
		if len(n.ALPN) > 0 {
			v.Set("alpn", strings.Join(n.ALPN, ","))
		}
		q(v, "fp", n.Fingerprint)
		if n.Insecure {
			v.Set("allowInsecure", "1")
		}
		q(v, "pbk", n.PublicKey)
		q(v, "sid", n.ShortID)
	}
	transport := func() {
		t := n.Network
		if t == "" {
			t = "tcp"
		}
		v.Set("type", t)
		q(v, "path", n.Path)
		q(v, "host", n.HostHeader)
		q(v, "serviceName", n.ServiceName)
	}
	withQuery := func(base string) string {
		if len(v) == 0 {
			return base + frag
		}
		return base + "?" + v.Encode() + frag
	}
	switch n.Proto {
	case SS:
		var ui string
		if strings.HasPrefix(n.Method, "2022-") {
			ui = url.PathEscape(n.Method) + ":" + url.PathEscape(n.Password)
		} else {
			ui = base64.RawURLEncoding.EncodeToString([]byte(n.Method + ":" + n.Password))
		}
		q(v, "plugin", n.Plugin)
		return withQuery("ss://" + ui + "@" + hp)
	case VLESS:
		v.Set("encryption", "none")
		q(v, "flow", n.Flow)
		transport()
		tls()
		return withQuery("vless://" + n.UUID + "@" + hp)
	case VMess:
		j := vmessJSON{PS: n.Name, Add: n.Host, Port: strconv.Itoa(n.Port), ID: n.UUID, Aid: strconv.Itoa(n.AlterID),
			Scy: firstNonEmpty(n.Method, "auto"), Net: map[string]string{"": "tcp", "http": "h2"}[n.Network], Host: n.HostHeader, Path: n.Path, SNI: n.SNI, FP: n.Fingerprint}
		if j.Net == "" {
			j.Net = n.Network
		}
		if n.Network == "grpc" {
			j.Path = n.ServiceName
		}
		if n.Security == "tls" {
			j.TLS = "tls"
		}
		j.ALPN = strings.Join(n.ALPN, ",")
		b, _ := json.Marshal(map[string]interface{}{"v": "2", "ps": j.PS, "add": j.Add, "port": j.Port, "id": j.ID, "aid": j.Aid,
			"scy": j.Scy, "net": j.Net, "type": "none", "host": j.Host, "path": j.Path, "tls": j.TLS, "sni": j.SNI, "alpn": j.ALPN, "fp": j.FP})
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case Trojan:
		transport()
		if n.Security == "" {
			n.Security = "tls"
		}
		tls()
		return withQuery("trojan://" + url.PathEscape(n.Password) + "@" + hp)
	case Socks, HTTP:
		scheme := "socks5"
		if n.Proto == HTTP {
			scheme = map[bool]string{true: "https", false: "http"}[n.Security == "tls"]
		} else if n.Version == 4 {
			scheme = "socks4"
		}
		ui := ""
		if n.Username != "" {
			ui = url.UserPassword(n.Username, n.Password).String() + "@"
		}
		return scheme + "://" + ui + hp + frag
	case Hysteria2:
		tls()
		q(v, "obfs", n.Extra["obfs"])
		q(v, "obfs-password", n.Extra["obfs_password"])
		q(v, "pinSHA256", n.Extra["pin_sha256"])
		return withQuery("hysteria2://" + url.PathEscape(n.Password) + "@" + hp)
	case Hysteria:
		tls()
		q(v, "auth", n.Password)
		q(v, "obfsParam", n.Extra["obfs"])
		q(v, "upmbps", n.Extra["up_mbps"])
		q(v, "downmbps", n.Extra["down_mbps"])
		return withQuery("hysteria://" + hp)
	case TUIC:
		tls()
		q(v, "congestion_control", n.Extra["congestion_control"])
		q(v, "udp_relay_mode", n.Extra["udp_relay_mode"])
		return withQuery("tuic://" + n.UUID + ":" + url.PathEscape(n.Password) + "@" + hp)
	case WireGuard:
		q(v, "publickey", n.Extra["public_key"])
		q(v, "presharedkey", n.Extra["pre_shared_key"])
		q(v, "address", n.Extra["address"])
		q(v, "reserved", n.Extra["reserved"])
		q(v, "mtu", n.Extra["mtu"])
		return withQuery("wireguard://" + url.PathEscape(n.Extra["private_key"]) + "@" + hp)
	case SSH:
		q(v, "private_key", n.Extra["private_key"])
		q(v, "private_key_passphrase", n.Extra["private_key_passphrase"])
		ui := ""
		if n.Username != "" {
			ui = url.UserPassword(n.Username, n.Password).String() + "@"
		}
		return withQuery("ssh://" + ui + hp)
	}
	return ""
}
