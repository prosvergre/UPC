// Package winui — нативное окно Windows (Walk) поверх ядра приложения
// internal/app. Файлы без суффикса _windows содержат только логику без
// зависимостей от Windows (поля формы, колонки таблицы), чтобы её можно было
// тестировать на любой системе.
package winui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"proxycheck/internal/node"
)

// Opt — вариант выпадающего списка.
type Opt struct{ Value, Label string }

// Kind — тип поля формы.
type Kind int

const (
	Text Kind = iota
	Password
	Number
	Select
	Check
	Area
)

// Field — поле формы ручного ввода. Ключ с префиксом "x:" пишется в Extra.
type Field struct {
	Key, Label string
	Kind       Kind
	Opts       []Opt
}

// ProtoInfo описывает протокол в форме.
type ProtoInfo struct {
	ID, Name string
	Fields   []Field
}

func opts(pairs ...string) []Opt {
	var o []Opt
	for i := 0; i+1 < len(pairs); i += 2 {
		o = append(o, Opt{pairs[i], pairs[i+1]})
	}
	return o
}

func same(vals ...string) []Opt {
	var o []Opt
	for _, v := range vals {
		o = append(o, Opt{v, v})
	}
	return o
}

var (
	ssMethods = same("aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
		"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "none")
	transportF = []Field{
		{"network", "Транспорт", Select, opts("", "tcp", "ws", "ws", "grpc", "grpc", "http", "http/h2", "httpupgrade", "httpupgrade")},
		{"path", "Путь (path)", Text, nil},
		{"host_header", "Host", Text, nil},
		{"service_name", "Служба gRPC", Text, nil},
	}
	tlsF = []Field{
		{"security", "Безопасность", Select, opts("", "нет", "tls", "tls", "reality", "reality")},
		{"sni", "SNI", Text, nil},
		{"alpn", "ALPN (через запятую)", Text, nil},
		{"fingerprint", "uTLS fingerprint", Select, opts("", "—", "chrome", "chrome", "firefox", "firefox", "safari", "safari", "ios", "ios", "android", "android", "edge", "edge", "random", "random", "randomized", "randomized")},
		{"insecure", "Не проверять сертификат", Check, nil},
		{"public_key", "Reality public key", Text, nil},
		{"short_id", "Reality short id", Text, nil},
	}
	muxF = []Field{
		{"x:mux", "Мультиплексирование", Select, opts("", "по умолчанию (выкл.)", "none", "выкл.", "smux", "smux", "yamux", "yamux", "h2mux", "h2mux")},
		{"x:mux_padding", "Padding мультиплекса", Check, nil},
		{"x:mux_max_streams", "Макс. потоков мультиплекса", Number, nil},
	}
	advF = []Field{{"x:outbound_json", "Доп. настройки outbound (JSON)", Area, nil}}
)

// Protocols — протоколы формы в порядке показа.
var Protocols = buildProtocols()

func buildProtocols() []ProtoInfo {
	cat := func(parts ...[]Field) []Field {
		var out []Field
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	withMux := func(f []Field) []Field { return cat(f, muxF, advF) }
	return []ProtoInfo{
		{node.SS, "Shadowsocks", withMux([]Field{
			{"method", "Шифрование", Select, ssMethods},
			{"password", "Пароль", Password, nil},
			{"x:plugin_name", "Плагин", Select, opts("", "—", "obfs-local", "obfs-local (simple-obfs)", "v2ray-plugin", "v2ray-plugin")},
			{"x:plugin_args", "Аргументы плагина", Text, nil},
			{"x:uot", "UoT (UDP over TCP)", Check, nil},
		})},
		{node.VLESS, "VLESS", withMux(cat([]Field{
			{"uuid", "UUID", Text, nil},
			{"flow", "Flow", Select, opts("", "—", "xtls-rprx-vision", "xtls-rprx-vision")},
		}, transportF, tlsF))},
		{node.VMess, "VMess", withMux(cat([]Field{
			{"uuid", "UUID", Text, nil},
			{"alter_id", "AlterID", Number, nil},
			{"method", "Шифрование", Select, same("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero")},
		}, transportF, tlsF))},
		{node.Trojan, "Trojan", withMux(cat([]Field{{"password", "Пароль", Password, nil}}, transportF, tlsF))},
		{node.Socks, "SOCKS", cat([]Field{
			{"version", "Версия", Select, same("5", "4")},
			{"username", "Логин", Text, nil}, {"password", "Пароль", Password, nil},
		}, advF)},
		{node.HTTP, "HTTP", cat([]Field{
			{"username", "Логин", Text, nil}, {"password", "Пароль", Password, nil},
			{"security", "HTTPS (TLS)", Select, opts("", "нет", "tls", "да")}, {"sni", "SNI", Text, nil},
		}, advF)},
		{node.Hysteria2, "Hysteria2", cat([]Field{
			{"password", "Пароль (auth)", Password, nil}, {"sni", "SNI", Text, nil},
			{"insecure", "Не проверять сертификат", Check, nil},
			{"x:obfs", "Obfs", Select, opts("", "нет", "salamander", "salamander")},
			{"x:obfs_password", "Obfs пароль", Text, nil},
		}, advF)},
		{node.Hysteria, "Hysteria", cat([]Field{
			{"password", "Auth", Text, nil}, {"sni", "SNI", Text, nil},
			{"insecure", "Не проверять сертификат", Check, nil},
			{"x:up_mbps", "Загрузка, Мбит/с", Number, nil}, {"x:down_mbps", "Скачивание, Мбит/с", Number, nil},
			{"x:obfs", "Obfs", Text, nil},
		}, advF)},
		{node.TUIC, "TUIC", cat([]Field{
			{"uuid", "UUID", Text, nil}, {"password", "Пароль", Password, nil},
			{"x:congestion_control", "Congestion", Select, opts("", "—", "bbr", "bbr", "cubic", "cubic", "new_reno", "new_reno")},
			{"x:udp_relay_mode", "UDP relay", Select, opts("", "—", "native", "native", "quic", "quic")},
			{"sni", "SNI", Text, nil}, {"alpn", "ALPN (через запятую)", Text, nil},
			{"insecure", "Не проверять сертификат", Check, nil},
		}, advF)},
		{node.WireGuard, "WireGuard", cat([]Field{
			{"x:private_key", "Private key", Password, nil}, {"x:public_key", "Public key пира", Text, nil},
			{"x:pre_shared_key", "Pre-shared key", Text, nil}, {"x:address", "Адрес (10.0.0.2/32)", Text, nil},
			{"x:reserved", "Reserved (1,2,3)", Text, nil}, {"x:mtu", "MTU", Number, nil},
		}, advF)},
		{node.SSH, "SSH", cat([]Field{
			{"username", "Пользователь", Text, nil}, {"password", "Пароль", Password, nil},
			{"x:private_key", "Приватный ключ", Area, nil},
		}, advF)},
	}
}

// ProtoByID возвращает описание протокола.
func ProtoByID(id string) (ProtoInfo, bool) {
	for _, p := range Protocols {
		if p.ID == id {
			return p, true
		}
	}
	return ProtoInfo{}, false
}

// CommonFields — поля, общие для всех протоколов (идут первыми).
var CommonFields = []Field{{"name", "Имя", Text, nil}, {"host", "Адрес", Text, nil}, {"port", "Порт", Number, nil}}

// BuildNode собирает сервер из значений формы. Значения check — "1" или "".
func BuildNode(proto string, v map[string]string) (node.Node, error) {
	info, ok := ProtoByID(proto)
	if !ok {
		return node.Node{}, fmt.Errorf("неизвестный протокол %q", proto)
	}
	n := node.Node{Proto: proto, Extra: map[string]string{}}
	get := func(k string) string { return strings.TrimSpace(v[k]) }
	n.Name, n.Host = get("name"), get("host")
	port, err := strconv.Atoi(get("port"))
	if err != nil || port <= 0 || port > 65535 {
		return node.Node{}, fmt.Errorf("порт должен быть числом от 1 до 65535")
	}
	n.Port = port
	for _, f := range info.Fields {
		val := get(f.Key)
		if strings.HasPrefix(f.Key, "x:") {
			if f.Kind == Check {
				if val == "1" {
					n.Extra[f.Key[2:]] = "1"
				}
			} else if val != "" {
				n.Extra[f.Key[2:]] = val
			}
			continue
		}
		switch f.Key {
		case "method":
			n.Method = val
		case "password":
			n.Password = val
		case "uuid":
			n.UUID = val
		case "flow":
			n.Flow = val
		case "alter_id":
			n.AlterID, _ = strconv.Atoi(val)
		case "network":
			n.Network = val
		case "path":
			n.Path = val
		case "host_header":
			n.HostHeader = val
		case "service_name":
			n.ServiceName = val
		case "security":
			n.Security = val
		case "sni":
			n.SNI = val
		case "alpn":
			for _, a := range strings.Split(val, ",") {
				if a = strings.TrimSpace(a); a != "" {
					n.ALPN = append(n.ALPN, a)
				}
			}
		case "fingerprint":
			n.Fingerprint = val
		case "insecure":
			n.Insecure = val == "1"
		case "public_key":
			n.PublicKey = val
		case "short_id":
			n.ShortID = val
		case "username":
			n.Username = val
		case "version":
			n.Version, _ = strconv.Atoi(val)
		}
	}
	switch proto { // эти протоколы всегда работают поверх TLS/QUIC
	case node.Hysteria, node.Hysteria2, node.TUIC, node.Trojan:
		if n.Security == "" {
			n.Security = "tls"
		}
	}
	if pn := n.Extra["plugin_name"]; pn != "" {
		n.Plugin = pn
		if pa := n.Extra["plugin_args"]; pa != "" {
			n.Plugin += ";" + pa
		}
	}
	delete(n.Extra, "plugin_name")
	delete(n.Extra, "plugin_args")
	if len(n.Extra) == 0 {
		n.Extra = nil
	}
	return n, nil
}

// ValuesFromNode раскладывает сервер по полям формы (для редактирования).
func ValuesFromNode(n node.Node) map[string]string {
	v := map[string]string{
		"name": n.Name, "host": n.Host, "port": strconv.Itoa(n.Port),
		"method": n.Method, "password": n.Password, "uuid": n.UUID, "flow": n.Flow,
		"network": n.Network, "path": n.Path, "host_header": n.HostHeader, "service_name": n.ServiceName,
		"security": n.Security, "sni": n.SNI, "alpn": strings.Join(n.ALPN, ","), "fingerprint": n.Fingerprint,
		"public_key": n.PublicKey, "short_id": n.ShortID, "username": n.Username,
	}
	if n.AlterID != 0 {
		v["alter_id"] = strconv.Itoa(n.AlterID)
	}
	if n.Insecure {
		v["insecure"] = "1"
	}
	if n.Proto == node.Socks {
		v["version"] = "5"
		if n.Version == 4 {
			v["version"] = "4"
		}
	}
	for k, x := range n.Extra {
		v["x:"+k] = x
	}
	if n.Plugin != "" {
		name, args, _ := strings.Cut(n.Plugin, ";")
		v["x:plugin_name"], v["x:plugin_args"] = name, args
	}
	return v
}

func sortStrings(a []string) { sort.Strings(a) }
