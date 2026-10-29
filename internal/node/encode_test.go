package node

import "testing"

func TestEncodeRoundTrip(t *testing.T) {
	raws := []string{
		"ss://2022-blake3-aes-256-gcm:YctPZ6U7xPGcUDq6gGh3gZXeHoUc9P4%2BmOcwM2Bp1Gs%3D@[2001:db8::1]:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket#ss22",
		"ss://YWVzLTI1Ni1nY206ZGVuaTE5ODM=@172.29.37.240:10001#Trixie%20-%20Over",
		"vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab12&type=grpc&serviceName=svc&flow=xtls-rprx-vision#r",
		"vless://11111111-2222-3333-4444-555555555555@h.com:443?security=tls&type=ws&path=/p&host=h.com&alpn=h2,http/1.1&allowInsecure=1",
		"vmess://eyJhZGQiOiIxMjkuMTQ2LjE0My44MCIsImFpZCI6IjAiLCJob3N0IjoiIiwiaWQiOiJkNDYwM2NjMi1lMGVlLTQ2NTEtODNmNS0xZGI1YjcxNjgxNzciLCJuZXQiOiJ0Y3AiLCJwYXRoIjoiIiwicG9ydCI6IjQ4MTExIiwicHMiOiJ2bWVzcy1VUyIsInNjeSI6ImF1dG8iLCJzbmkiOiIiLCJ0bHMiOiIiLCJ0eXBlIjoibm9uZSIsInYiOiIyIn0=",
		"trojan://pw@h.com:443?security=tls&sni=a.com&type=ws&path=/x%3Dy&host=a.com#t",
		"socks5://u:p@1.2.3.4:1080#s", "socks4://1.2.3.4:1080", "http://Prox:pass@189.110.65.145:3001#MiSina",
		"hysteria2://auth@h.com:443?sni=a.com&obfs=salamander&obfs-password=x&insecure=1#h2",
		"hysteria://h.com:443?auth=abc&peer=a.com&upmbps=10&downmbps=50&insecure=1",
		"tuic://11111111-2222-3333-4444-555555555555:pw@h.com:443?congestion_control=bbr&alpn=h3&udp_relay_mode=native",
		"wireguard://yAnz5TF%2BlXXJte14tji3zlMNq%2BhdzrKWhIOdsbUlcn8%3D@10.1.1.1:51820?publickey=bw4aLaVVVoRKFUcJmaZwFaZQ3gQ8mfF0i3o2dD3Yh0Q%3D&address=10.0.0.2/32&reserved=1,2,3",
		"ssh://root:pw@11.11.11.11:22",
	}
	for _, raw := range raws {
		a, err := Parse(raw)
		if err != nil {
			t.Fatalf("%.50s: %v", raw, err)
		}
		link := Encode(a)
		b, err := Parse(link)
		if err != nil {
			t.Fatalf("encode→parse %.50s: %v (link %q)", raw, err, link)
		}
		if a.ID() != b.ID() {
			t.Errorf("ID изменился: %.60s\n a=%+v\n b=%+v\n link=%s", raw, a, b, link)
		}
		if b.Name != a.Name {
			t.Errorf("имя: %q != %q", a.Name, b.Name)
		}
	}
}

func TestSummary(t *testing.T) {
	cases := map[string]string{
		"ss://YWVzLTI1Ni1nY206cHc=@1.1.1.1:1":                                         "aes-256-gcm",
		"vless://11111111-2222-3333-4444-555555555555@h.com:443?security=tls&type=ws": "ws · tls",
		"trojan://pw@h.com:443":                                                       "tcp · tls",
		"hysteria2://a@h.com:443?obfs=salamander":                                     "obfs:salamander · tls",
		"socks5://u:p@1.1.1.1:1":                                                      "v5 · auth",
	}
	for raw, want := range cases {
		n, err := Parse(raw)
		if err != nil || n.Summary() != want {
			t.Errorf("%s: %q (want %q) %v", raw, n.Summary(), want, err)
		}
	}
}
