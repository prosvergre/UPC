package winui

import (
	"testing"

	"proxycheck/internal/node"
)

func TestBuildNodeEveryProtocolRoundTrips(t *testing.T) {
	const key = "yAnz5TF+lXXJte14tji3zlMNq+hdzrKWhIOdsbUlcn8="
	cases := map[string]map[string]string{
		node.SS:        {"name": "a", "host": "1.1.1.1", "port": "8388", "method": "aes-256-gcm", "password": "pw", "x:plugin_name": "obfs-local", "x:plugin_args": "obfs=tls", "x:uot": "1", "x:mux": "smux"},
		node.VLESS:     {"name": "b", "host": "h.com", "port": "443", "uuid": "11111111-2222-3333-4444-555555555555", "flow": "xtls-rprx-vision", "network": "ws", "path": "/p", "host_header": "h.com", "security": "tls", "sni": "h.com", "alpn": "h2, http/1.1", "insecure": "1"},
		node.VMess:     {"name": "c", "host": "h.com", "port": "443", "uuid": "11111111-2222-3333-4444-555555555555", "alter_id": "0", "method": "auto", "network": "grpc", "service_name": "svc", "security": "tls"},
		node.Trojan:    {"name": "d", "host": "h.com", "port": "443", "password": "pw", "security": "tls", "sni": "a.com"},
		node.Socks:     {"name": "e", "host": "1.2.3.4", "port": "1080", "version": "4"},
		node.HTTP:      {"name": "f", "host": "1.2.3.4", "port": "8080", "username": "u", "password": "p"},
		node.Hysteria2: {"name": "g", "host": "h.com", "port": "443", "password": "auth", "sni": "a.com", "x:obfs": "salamander", "x:obfs_password": "x"},
		node.Hysteria:  {"name": "h", "host": "h.com", "port": "443", "password": "auth", "x:up_mbps": "10", "x:down_mbps": "50"},
		node.TUIC:      {"name": "i", "host": "h.com", "port": "443", "uuid": "11111111-2222-3333-4444-555555555555", "password": "pw", "x:congestion_control": "bbr"},
		node.WireGuard: {"name": "j", "host": "10.1.1.1", "port": "51820", "x:private_key": key, "x:public_key": key, "x:address": "10.0.0.2/32"},
		node.SSH:       {"name": "k", "host": "11.11.11.11", "port": "22", "username": "root", "password": "pw"},
	}
	if len(cases) != len(Protocols) {
		t.Fatalf("форма знает %d протоколов, тест покрывает %d", len(Protocols), len(cases))
	}
	for proto, vals := range cases {
		n, err := BuildNode(proto, vals)
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		if err := node.Validate(n); err != nil {
			t.Fatalf("%s: validate: %v", proto, err)
		}
		back, err := node.Parse(node.Encode(n))
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		if back.ID() != n.ID() {
			t.Errorf("%s: ID после Encode/Parse изменился", proto)
		}
		// форма -> узел -> форма -> узел даёт тот же узел
		n2, err := BuildNode(proto, ValuesFromNode(n))
		if err != nil || n2.ID() != n.ID() || n2.Plugin != n.Plugin || n2.Extra["uot"] != n.Extra["uot"] {
			t.Errorf("%s: редактирование теряет данные: %+v vs %+v (%v)", proto, n, n2, err)
		}
	}
}

func TestBuildNodeRejectsBadPort(t *testing.T) {
	for _, p := range []string{"", "0", "70000", "abc"} {
		if _, err := BuildNode(node.SS, map[string]string{"host": "h", "port": p}); err == nil {
			t.Errorf("порт %q должен отклоняться", p)
		}
	}
	if _, err := BuildNode("nope", nil); err == nil {
		t.Error("неизвестный протокол")
	}
}
