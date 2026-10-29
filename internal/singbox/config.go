// Package singbox генерирует конфиг для sing-box (один процесс на все линии),
// управляет процессом и общается с ним через Clash API.
package singbox

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"proxycheck/internal/node"
)

type obj = map[string]interface{}

// Line — одна локальная линия: порт входа и текущий выбранный сервер.
type Line struct {
	Port   int    // локальный порт (mixed: socks5+http)
	NodeID string // node.ID() выбранного сервера
}

// Spec — описание того, что должно работать в процессе.
type Spec struct {
	Nodes     []node.Node // все серверы, которые должны быть доступны как outbound
	Lines     []Line      // входы; у каждого свой selector, переключаемый через API без рестарта
	Listen    string      // адрес входов, по умолчанию 127.0.0.1
	ClashAddr string      // например 127.0.0.1:19090
	Secret    string
	LogLevel  string // warn по умолчанию
}

// Tag возвращает тег outbound для сервера.
func Tag(n node.Node) string { return "o-" + n.ID() }

// SelectorTag — тег selector'а линии.
func SelectorTag(port int) string { return "sel-" + strconv.Itoa(port) }

// InboundTag — тег входа линии.
func InboundTag(port int) string { return "in-" + strconv.Itoa(port) }

// BuildConfig строит JSON конфига. Серверы с невозможными для ядра
// параметрами пропускаются; список пропущенных возвращается вторым значением.
func BuildConfig(s Spec) ([]byte, map[string]error, error) {
	if s.Listen == "" {
		s.Listen = "127.0.0.1"
	}
	if s.LogLevel == "" {
		s.LogLevel = "warn"
	}
	skipped := map[string]error{}
	var outbounds, endpoints []interface{}
	var tags []string
	seen := map[string]bool{}
	for _, n := range s.Nodes {
		tag := Tag(n)
		if seen[tag] {
			continue
		}
		seen[tag] = true
		if err := node.Validate(n); err != nil {
			skipped[n.ID()] = err
			continue
		}
		o, isEndpoint, err := nodeObject(n, tag)
		if err != nil {
			skipped[n.ID()] = err
			continue
		}
		if isEndpoint {
			endpoints = append(endpoints, o)
		} else {
			outbounds = append(outbounds, o)
		}
		tags = append(tags, tag)
	}
	if len(tags) == 0 && len(s.Lines) > 0 {
		return nil, skipped, fmt.Errorf("нет ни одного пригодного сервера для конфига")
	}

	var inbounds, rules []interface{}
	for _, l := range s.Lines {
		sel := SelectorTag(l.Port)
		in := InboundTag(l.Port)
		def := ""
		for _, n := range s.Nodes {
			if n.ID() == l.NodeID && !contains(skipped, n.ID()) {
				def = Tag(n)
			}
		}
		if def == "" {
			def = tags[0]
		}
		inbounds = append(inbounds, obj{"type": "mixed", "tag": in, "listen": s.Listen, "listen_port": l.Port})
		outbounds = append(outbounds, obj{"type": "selector", "tag": sel, "outbounds": tags, "default": def, "interrupt_exist_connections": true})
		rules = append(rules, obj{"inbound": []string{in}, "outbound": sel})
	}
	outbounds = append(outbounds, obj{"type": "direct", "tag": "direct"})

	cfg := obj{
		"log":       obj{"level": s.LogLevel, "timestamp": true},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     obj{"rules": rules, "final": "direct"},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	if s.ClashAddr != "" {
		cfg["experimental"] = obj{"clash_api": obj{"external_controller": s.ClashAddr, "secret": s.Secret}}
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	return b, skipped, err
}

func contains(m map[string]error, k string) bool { _, ok := m[k]; return ok }

// nodeObject переводит Node в outbound (или endpoint для wireguard).
func nodeObject(n node.Node, tag string) (obj, bool, error) {
	o := obj{"tag": tag, "server": n.Host, "server_port": n.Port}
	switch n.Proto {
	case node.SS:
		o["type"] = "shadowsocks"
		o["method"], o["password"] = n.Method, n.Password
		if n.Plugin != "" {
			name, opts, _ := strings.Cut(n.Plugin, ";")
			o["plugin"], o["plugin_opts"] = name, opts
		}
	case node.VLESS:
		o["type"] = "vless"
		if n.UUID == "" {
			return nil, false, fmt.Errorf("vless: нет uuid")
		}
		o["uuid"] = n.UUID
		if n.Flow != "" {
			o["flow"] = n.Flow
		}
		addTLS(o, n)
		addTransport(o, n)
	case node.VMess:
		o["type"] = "vmess"
		o["uuid"], o["security"], o["alter_id"] = n.UUID, firstNonEmpty(n.Method, "auto"), n.AlterID
		addTLS(o, n)
		addTransport(o, n)
	case node.Trojan:
		o["type"] = "trojan"
		o["password"] = n.Password
		addTLS(o, n)
		addTransport(o, n)
	case node.Socks:
		o["type"] = "socks"
		o["version"] = strconv.Itoa(map[bool]int{true: n.Version, false: 5}[n.Version != 0])
		if n.Username != "" {
			o["username"], o["password"] = n.Username, n.Password
		}
	case node.HTTP:
		o["type"] = "http"
		if n.Username != "" {
			o["username"], o["password"] = n.Username, n.Password
		}
		addTLS(o, n)
	case node.Hysteria:
		o["type"] = "hysteria"
		if n.Password != "" {
			o["auth_str"] = n.Password
		}
		o["up_mbps"], o["down_mbps"] = intOr(n.Extra["up_mbps"], 20), intOr(n.Extra["down_mbps"], 100)
		if v := n.Extra["obfs"]; v != "" {
			o["obfs"] = v
		}
		addTLS(o, n)
	case node.Hysteria2:
		o["type"] = "hysteria2"
		o["password"] = n.Password
		if n.Extra["obfs"] != "" {
			o["obfs"] = obj{"type": n.Extra["obfs"], "password": n.Extra["obfs_password"]}
		}
		addTLS(o, n)
	case node.TUIC:
		o["type"] = "tuic"
		o["uuid"], o["password"] = n.UUID, n.Password
		if v := n.Extra["congestion_control"]; v != "" {
			o["congestion_control"] = v
		}
		if v := n.Extra["udp_relay_mode"]; v != "" {
			o["udp_relay_mode"] = v
		}
		addTLS(o, n)
	case node.SSH:
		o["type"] = "ssh"
		o["user"] = firstNonEmpty(n.Username, "root")
		if n.Password != "" {
			o["password"] = n.Password
		}
		if n.Extra["private_key"] != "" {
			o["private_key"] = n.Extra["private_key"]
		}
		if n.Extra["private_key_passphrase"] != "" {
			o["private_key_passphrase"] = n.Extra["private_key_passphrase"]
		}
		if n.Password == "" && n.Extra["private_key"] == "" {
			return nil, false, fmt.Errorf("ssh: нет пароля и ключа")
		}
	case node.WireGuard:
		peer := obj{"address": n.Host, "port": n.Port, "public_key": n.Extra["public_key"], "allowed_ips": []string{"0.0.0.0/0", "::/0"}}
		if v := n.Extra["pre_shared_key"]; v != "" {
			peer["pre_shared_key"] = v
		}
		if r := parseReserved(n.Extra["reserved"]); r != nil {
			peer["reserved"] = r
		}
		addr := []string{}
		for _, a := range strings.Split(firstNonEmpty(n.Extra["address"], "10.0.0.2/32"), ",") {
			if a = strings.TrimSpace(a); a != "" {
				if !strings.Contains(a, "/") {
					a += "/32"
				}
				addr = append(addr, a)
			}
		}
		e := obj{"type": "wireguard", "tag": tag, "address": addr, "private_key": n.Extra["private_key"], "peers": []interface{}{peer}}
		if m := intOr(n.Extra["mtu"], 0); m > 0 {
			e["mtu"] = m
		}
		return e, true, nil
	default:
		return nil, false, fmt.Errorf("протокол %q не поддерживается", n.Proto)
	}
	if n.Proto == node.SS && n.Extra["uot"] == "1" {
		o["udp_over_tcp"] = true
	}
	if m := n.Extra["mux"]; m != "" && m != "none" {
		switch n.Proto {
		case node.SS, node.VLESS, node.VMess, node.Trojan:
			mux := obj{"enabled": true, "protocol": m}
			if v := intOr(n.Extra["mux_max_streams"], 0); v > 0 {
				mux["max_streams"] = v
			}
			if n.Extra["mux_padding"] == "1" {
				mux["padding"] = true
			}
			o["multiplex"] = mux
		}
	}
	if raw := strings.TrimSpace(n.Extra["outbound_json"]); raw != "" {
		var extra map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &extra); err != nil {
			return nil, false, fmt.Errorf("доп. настройки outbound: %v", err)
		}
		for k, v := range extra {
			if k == "tag" { // тег служебный
				continue
			}
			o[k] = v
		}
	}
	return o, false, nil
}

func addTLS(o obj, n node.Node) {
	if n.Security == "" {
		return
	}
	t := obj{"enabled": true}
	if n.SNI != "" {
		t["server_name"] = n.SNI
	}
	if n.Insecure {
		t["insecure"] = true
	}
	if len(n.ALPN) > 0 {
		t["alpn"] = n.ALPN
	}
	// pinSHA256 у hysteria2 — отпечаток сертификата (другой формат, чем ждёт
	// ядро). Серверы с пином обычно самоподписанные: для проверки доступности
	// принимаем сертификат как есть.
	if n.Extra["pin_sha256"] != "" {
		t["insecure"] = true
	}
	fp := n.Fingerprint
	if n.Security == "reality" {
		if fp == "" {
			fp = "chrome"
		}
		t["reality"] = obj{"enabled": true, "public_key": n.PublicKey, "short_id": n.ShortID}
	}
	if fp != "" && n.Proto != node.Hysteria && n.Proto != node.Hysteria2 && n.Proto != node.TUIC {
		t["utls"] = obj{"enabled": true, "fingerprint": fp}
	}
	o["tls"] = t
}

func addTransport(o obj, n node.Node) {
	switch n.Network {
	case "":
		return
	case "ws":
		t := obj{"type": "ws", "path": firstNonEmpty(n.Path, "/")}
		if n.HostHeader != "" {
			t["headers"] = obj{"Host": n.HostHeader}
		}
		o["transport"] = t
	case "grpc":
		o["transport"] = obj{"type": "grpc", "service_name": n.ServiceName}
	case "http":
		t := obj{"type": "http", "path": firstNonEmpty(n.Path, "/")}
		if n.HostHeader != "" {
			t["host"] = strings.Split(n.HostHeader, ",")
		}
		o["transport"] = t
	case "httpupgrade":
		t := obj{"type": "httpupgrade", "path": firstNonEmpty(n.Path, "/")}
		if n.HostHeader != "" {
			t["host"] = n.HostHeader
		}
		o["transport"] = t
	}
}

func parseReserved(s string) []int {
	if s == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil
		}
		out = append(out, v)
	}
	if len(out) != 3 {
		return nil
	}
	return out
}

func intOr(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
