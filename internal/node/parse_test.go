package node

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestSS(t *testing.T) {
	// SIP002
	n, err := Parse("ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pa55")) + "@1.2.3.4:8388#My%20Name")
	if err != nil || n.Method != "aes-256-gcm" || n.Password != "pa55" || n.Host != "1.2.3.4" || n.Port != 8388 || n.Name != "My Name" {
		t.Fatalf("sip002: %+v %v", n, err)
	}
	// legacy
	n, err = Parse("ss://" + b64("chacha20-ietf-poly1305:pw@example.com:443") + "#x")
	if err != nil || n.Host != "example.com" || n.Port != 443 || n.Method != "chacha20-ietf-poly1305" {
		t.Fatalf("legacy: %+v %v", n, err)
	}
	// SS2022: method:key в процентном кодировании, ключ содержит '='
	n, err = Parse("ss://2022-blake3-aes-256-gcm:YctPZ6U7xPGcUDq6gGh3gZXeHoUc9P4%2BmOcwM2Bp1Gs%3D@[2001:db8::1]:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket#ss22")
	if err != nil || n.Method != "2022-blake3-aes-256-gcm" || n.Password != "YctPZ6U7xPGcUDq6gGh3gZXeHoUc9P4+mOcwM2Bp1Gs=" ||
		n.Host != "2001:db8::1" || n.Plugin != "v2ray-plugin;mode=websocket" {
		t.Fatalf("ss2022: %+v %v", n, err)
	}
}

func TestVMess(t *testing.T) {
	j := `{"v":"2","ps":"vm","add":"vm.example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"ws","host":"h.example.com","path":"/ws","tls":"tls","sni":"s.example.com"}`
	n, err := Parse("vmess://" + b64(j))
	if err != nil || n.Proto != VMess || n.Port != 443 || n.Network != "ws" || n.Security != "tls" || n.SNI != "s.example.com" || n.Path != "/ws" {
		t.Fatalf("%+v %v", n, err)
	}
}

func TestVLESSReality(t *testing.T) {
	n, err := Parse("vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUB&sid=ab12&type=tcp&flow=xtls-rprx-vision#r")
	if err != nil || n.Security != "reality" || n.PublicKey != "PUB" || n.ShortID != "ab12" || n.Flow != "xtls-rprx-vision" || n.Network != "" {
		t.Fatalf("%+v %v", n, err)
	}
	n, err = Parse("vless://u@h.com:443?type=grpc&serviceName=svc&security=tls&alpn=h2,http/1.1")
	if err != nil || n.Network != "grpc" || n.ServiceName != "svc" || len(n.ALPN) != 2 {
		t.Fatalf("%+v %v", n, err)
	}
}

func TestOthers(t *testing.T) {
	cases := map[string]string{
		"trojan://pw@h.com:443?sni=a.com#t": Trojan,
		"socks5://u:p@1.2.3.4:1080":         Socks,
		"socks4://1.2.3.4:1080":             Socks,
		"http://u:p@1.2.3.4:8080":           HTTP,
		"hysteria2://auth@h.com:443?sni=a.com&obfs=salamander&obfs-password=x#h2":                 Hysteria2,
		"hy2://auth@h.com:443?insecure=1":                                                         Hysteria2,
		"hysteria://h.com:443?auth=abc&peer=a.com&upmbps=10&downmbps=50&insecure=1":               Hysteria,
		"tuic://11111111-2222-3333-4444-555555555555:pw@h.com:443?congestion_control=bbr&alpn=h3": TUIC,
		"wireguard://PRIV@h.com:51820?publickey=PUB&address=10.0.0.2/32&reserved=1,2,3":           WireGuard,
		"ssh://root:pw@h.com:22": SSH,
	}
	for raw, proto := range cases {
		n, err := Parse(raw)
		if err != nil || n.Proto != proto {
			t.Errorf("%s: %+v %v", raw, n, err)
		}
	}
	if n, _ := Parse("socks4://1.2.3.4:1080"); n.Version != 4 {
		t.Error("socks4 version")
	}
	if n, _ := Parse("hysteria2://auth@h.com:443"); n.Security != "tls" {
		t.Error("hy2 tls default")
	}
	if _, err := Parse("wireguard://PRIV@h.com:51820"); err == nil {
		t.Error("wireguard без public key должен падать")
	}
}

func TestExtractAll(t *testing.T) {
	text := "# comment http://example.com/page\nss://" + b64("aes-128-gcm:p@1.1.1.1:1") + "#a\nvless://u@h.com:443?security=tls\nhttp://9.9.9.9:3128\nhttps://github.com/foo/bar\nbad://x\n"
	got := ExtractAll(text)
	if len(got) != 3 {
		t.Fatalf("ожидалось 3, получено %d: %+v", len(got), got)
	}
	// base64-подписка целиком
	got = ExtractAll(b64(text))
	if len(got) != 3 {
		t.Fatalf("base64: ожидалось 3, получено %d", len(got))
	}
}

func TestIDDistinguishesAccounts(t *testing.T) {
	a, _ := Parse("trojan://aaa@h.com:443")
	b, _ := Parse("trojan://bbb@h.com:443")
	if a.ID() == b.ID() {
		t.Fatal("разные аккаунты должны иметь разный ID")
	}
}

func TestLegacySettingsJSON(t *testing.T) {
	var n Node
	err := json.Unmarshal([]byte(`{"Remarks":"old","Method":"aes-256-gcm","Password":"p","Host":"1.2.3.4","Port":8388,"Raw":"ss://x"}`), &n)
	if err != nil || n.Proto != SS || n.Name != "old" || n.Host != "1.2.3.4" || n.Port != 8388 {
		t.Fatalf("%+v %v", n, err)
	}
	b, _ := json.Marshal(n)
	var m Node
	if err := json.Unmarshal(b, &m); err != nil || m.ID() != n.ID() {
		t.Fatalf("round trip: %+v %v", m, err)
	}
}

func TestVlessFlowNormalizedAndValidated(t *testing.T) {
	n, err := Parse("vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?flow=xtls-rprx-vision-udp443&security=tls")
	if err != nil || n.Flow != "xtls-rprx-vision" || Validate(n) != nil {
		t.Fatalf("%+v %v", n, err)
	}
	n, _ = Parse("vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?flow=weird")
	if Validate(n) == nil {
		t.Fatal("неизвестный flow должен отклоняться")
	}
}

func TestUserSamples(t *testing.T) {
	samples := []struct {
		raw, proto, host string
		port             int
		nameHas          string
	}{
		{"ss://YWVzLTEyOC1nY206c2hhZG93c29ja3M=@141.98.101.181:443#%F0%9F%87%AC%F0%9F%87%A7%20United%20Kingdom%20-%20Manchester%20%F0%9F%8C%8D%20SS-TCP-NA%204%20-%20ETOT%20WAS%20-%20%206:47:59%20%2028.10.2026%20%D0%A1%D1%80%20%F0%9F%A1%85%20=%20XX%20%F0%9F%A1%87%20=%20XX", SS, "141.98.101.181", 443, "United Kingdom"},
		{"vless://931729a8-3c20-4841-89a1-f18dc9ce0a6f@cdn9-33.vk-cdnvideo.com:8443?security=tls&type=tcp&encryption=none#%F0%9F%87%A9%F0%9F%87%AA[openproxylist.com]%20vless-DE%20-%20ETOT%20BJL%20-%2009.06.2026%20%D0%92%D1%82%20-%2027.06.2026%20%D0%A1%D0%B1%20%F0%9F%A1%85%20=%2078%20%F0%9F%A1%87%20=%20184", VLESS, "cdn9-33.vk-cdnvideo.com", 8443, "vless-DE"},
		{"vmess://eyJhZGQiOiIxMjkuMTQ2LjE0My44MCIsImFpZCI6IjAiLCJob3N0IjoiIiwiaWQiOiJkNDYwM2NjMi1lMGVlLTQ2NTEtODNmNS0xZGI1YjcxNjgxNzciLCJuZXQiOiJ0Y3AiLCJwYXRoIjoiIiwicG9ydCI6IjQ4MTExIiwicHMiOiLwn4e68J+HuFtvcGVucHJveHlsaXN0LmNvbV0gdm1lc3MtVVMiLCJzY3kiOiJhdXRvIiwic25pIjoiIiwidGxzIjoiIiwidHlwZSI6Im5vbmUiLCJ2IjoiMiJ9", VMess, "129.146.143.80", 48111, "vmess-US"},
		{"trojan://22367c45-f6c4-4ca8-8d52-d9787d7bbe91@104.16.149.10:443?security=tls&sni=cm2-bpg.filegear-sg.me&allowInsecure=1&type=ws&path=/proxyip%3D210.61.97.241:81&host=cm2-bpg.filegear-sg.me#%F0%9F%94%92%20TR-WS-TLS%20%F0%9F%8F%B4%E2%80%8D%E2%98%A0%EF%B8%8F%20NA-104.16.149.10:443%20%F0%9F%93%A1%20PING-001.75-MS", Trojan, "104.16.149.10", 443, "TR-WS-TLS"},
		{"ss://YWVzLTI1Ni1nY206ZGVuaTE5ODM=@172.29.37.240:10001#Trixie%20-%20Over%20ZRT%20raspi%20-%20xray", SS, "172.29.37.240", 10001, "Trixie"},
		{"http://Prox:pass@189.110.65.145:3001#MiSina%20HTTP", HTTP, "189.110.65.145", 3001, "MiSina HTTP"},
	}
	var all strings.Builder
	for _, s := range samples {
		n, err := Parse(s.raw)
		if err != nil {
			t.Errorf("%.40s: %v", s.raw, err)
			continue
		}
		if n.Proto != s.proto || n.Host != s.host || n.Port != s.port || !strings.Contains(n.Name, s.nameHas) {
			t.Errorf("%.40s: %+v", s.raw, n)
		}
		if err := Validate(n); err != nil {
			t.Errorf("Validate %.40s: %v", s.raw, err)
		}
		all.WriteString(s.raw + "\n")
	}
	if got := ExtractAll(all.String()); len(got) != len(samples) {
		t.Errorf("ExtractAll: %d из %d", len(got), len(samples))
	}
	if n, _ := Parse(samples[3].raw); n.Network != "ws" || n.Path != "/proxyip=210.61.97.241:81" || !n.Insecure || n.SNI != "cm2-bpg.filegear-sg.me" {
		t.Errorf("trojan поля: %+v", n)
	}
	if n, _ := Parse(samples[5].raw); n.Username != "Prox" || n.Password != "pass" {
		t.Errorf("http учётка: %+v", n)
	}
}
