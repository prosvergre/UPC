// Package node — единая модель прокси-сервера любого протокола и парсеры
// ссылок (ss, vless, vmess, trojan, socks, http, hysteria, hysteria2, tuic,
// wireguard, ssh). Пакет использует только стандартную библиотеку.
package node

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

// Протоколы.
const (
	SS        = "ss"
	VLESS     = "vless"
	VMess     = "vmess"
	Trojan    = "trojan"
	Socks     = "socks"
	HTTP      = "http"
	Hysteria  = "hysteria"
	Hysteria2 = "hysteria2"
	TUIC      = "tuic"
	WireGuard = "wireguard"
	SSH       = "ssh"
)

// Node описывает один сервер. Поля общие для всех протоколов; специфичные
// лежат в Extra (ключи описаны рядом с парсерами).
type Node struct {
	Proto string `json:"proto"`
	Name  string `json:"name,omitempty"`
	Host  string `json:"host"`
	Port  int    `json:"port"`

	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"` // ss/trojan/socks/http/ssh/hysteria2 auth/tuic
	UUID     string `json:"uuid,omitempty"`     // vless/vmess/tuic
	Method   string `json:"method,omitempty"`   // ss: шифр; vmess: security
	Flow     string `json:"flow,omitempty"`
	AlterID  int    `json:"alter_id,omitempty"`
	Version  int    `json:"version,omitempty"` // socks: 4/5

	Network     string `json:"network,omitempty"` // "", tcp, ws, grpc, http, httpupgrade
	Path        string `json:"path,omitempty"`
	HostHeader  string `json:"host_header,omitempty"`
	ServiceName string `json:"service_name,omitempty"`

	Security    string   `json:"security,omitempty"` // "", tls, reality
	SNI         string   `json:"sni,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`
	PublicKey   string   `json:"public_key,omitempty"` // reality pbk
	ShortID     string   `json:"short_id,omitempty"`

	Plugin string `json:"plugin,omitempty"` // ss plugin (obfs-local;obfs=tls ...)

	Extra map[string]string `json:"extra,omitempty"`
	Raw   string            `json:"raw,omitempty"`
}

// Addr возвращает host:port.
func (n Node) Addr() string {
	h := n.Host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return fmt.Sprintf("%s:%d", h, n.Port)
}

// ID — стабильный идентификатор для дедупликации: протокол + адрес +
// учётные данные (два разных аккаунта на одном хосте — разные серверы).
func (n Node) ID() string {
	h := sha1.Sum([]byte(strings.Join([]string{n.Proto, strings.ToLower(n.Host), fmt.Sprint(n.Port),
		n.Username, n.Password, n.UUID, n.Method, n.Network, n.Path, n.Security, n.SNI, n.Extra["private_key"]}, "|")))
	return n.Proto + "-" + hex.EncodeToString(h[:6])
}

// Label — короткая подпись для списка.
func (n Node) Label() string {
	if n.Name != "" {
		return n.Name
	}
	return n.Proto + " " + n.Addr()
}

func (n *Node) extra(k, v string) {
	if v == "" {
		return
	}
	if n.Extra == nil {
		n.Extra = map[string]string{}
	}
	n.Extra[k] = v
}
