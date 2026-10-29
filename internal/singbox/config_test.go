package singbox

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"proxycheck/internal/node"
)

func TestBuildConfigAllProtocols(t *testing.T) {
	raws := []string{
		"ss://2022-blake3-aes-256-gcm:YctPZ6U7xPGcUDq6gGh3gZXeHoUc9P4%2BmOcwM2Bp1Gs%3D@1.1.1.1:8388#a",
		"vless://11111111-2222-3333-4444-555555555555@2.2.2.2:443?security=reality&sni=x.com&pbk=rG7q1o7jgPdCBuHfFfWaotPq_EpqnpahrLjz04gRKu4&sid=ab&flow=xtls-rprx-vision&type=ws&path=/p&host=h.com",
		"trojan://pw@3.3.3.3:443?sni=a.com",
		"socks5://u:p@4.4.4.4:1080",
		"socks4://5.5.5.5:1080",
		"http://6.6.6.6:8080",
		"hysteria2://auth@7.7.7.7:443?obfs=salamander&obfs-password=x",
		"hysteria://8.8.8.8:443?auth=abc&upmbps=10&downmbps=50",
		"tuic://11111111-2222-3333-4444-555555555555:pw@9.9.9.9:443?congestion_control=bbr",
		"wireguard://euVtUSO57OWmqYpiVGsiOvK5VH4lFjGJeZ6Rv64UHs0%3D@10.1.1.1:51820?publickey=H01g%2FDLY2x29jY7FeEi0LAPvyRWMdaL6aycx8fPvCGc%3D&address=10.0.0.2/32&reserved=1,2,3",
		"ssh://root:pw@11.11.11.11:22",
	}
	var nodes []node.Node
	for _, r := range raws {
		n, err := node.Parse(r)
		if err != nil {
			t.Fatal(r, err)
		}
		nodes = append(nodes, n)
	}
	b, skipped, err := BuildConfig(Spec{Nodes: nodes, Lines: []Line{{Port: 1080, NodeID: nodes[2].ID()}, {Port: 1081, NodeID: nodes[9].ID()}}, ClashAddr: "127.0.0.1:19090"})
	if err != nil || len(skipped) != 0 {
		t.Fatal(err, skipped)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg["endpoints"].([]interface{})) != 1 {
		t.Error("wireguard должен быть endpoint'ом")
	}
	// 10 outbound + 2 selector + direct
	if got := len(cfg["outbounds"].([]interface{})); got != 10+2+1 {
		t.Errorf("outbounds=%d", got)
	}
	if len(cfg["inbounds"].([]interface{})) != 2 {
		t.Error("inbounds")
	}
}

func TestBuildConfigSkipsBroken(t *testing.T) {
	good, _ := node.Parse("trojan://pw@3.3.3.3:443")
	bad := node.Node{Proto: "ssh", Host: "h", Port: 22} // нет ни пароля, ни ключа
	_, skipped, err := BuildConfig(Spec{Nodes: []node.Node{good, bad}, Lines: []Line{{Port: 1080, NodeID: good.ID()}}})
	if err != nil || len(skipped) != 1 {
		t.Fatal(err, skipped)
	}
}

func TestRealSingboxCheck(t *testing.T) {
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		t.Skip("SINGBOX_BIN не задан")
	}
	raws := []string{
		"ss://2022-blake3-aes-256-gcm:YctPZ6U7xPGcUDq6gGh3gZXeHoUc9P4%2BmOcwM2Bp1Gs%3D@1.1.1.1:8388#a",
		"ss://" + "YWVzLTI1Ni1nY206cHc" + "@1.1.1.2:8388",
		"vless://11111111-2222-3333-4444-555555555555@2.2.2.2:443?security=reality&sni=x.com&pbk=h1f3uHiukZY2-zJ8zlZ_OzsAzGOazvLmAkyItbLYKog&sid=ab&flow=xtls-rprx-vision",
		"vless://11111111-2222-3333-4444-555555555555@2.2.2.3:443?security=tls&type=ws&path=/p&host=h.com&sni=h.com",
		"vless://11111111-2222-3333-4444-555555555555@2.2.2.4:443?security=tls&type=grpc&serviceName=s",
		"trojan://pw@3.3.3.3:443?sni=a.com",
		"socks5://u:p@4.4.4.4:1080",
		"socks4://5.5.5.5:1080",
		"http://6.6.6.6:8080",
		"hysteria2://auth@7.7.7.7:443?obfs=salamander&obfs-password=x&insecure=1",
		"hysteria://8.8.8.8:443?auth=abc&upmbps=10&downmbps=50&insecure=1",
		"tuic://11111111-2222-3333-4444-555555555555:pw@9.9.9.9:443?congestion_control=bbr&alpn=h3",
		"wireguard://" + "yAnz5TF%2BlXXJte14tji3zlMNq%2BhdzrKWhIOdsbUlcn8%3D" + "@10.1.1.1:51820?publickey=" + "bw4aLaVVVoRKFUcJmaZwFaZQ3gQ8mfF0i3o2dD3Yh0Q%3D" + "&address=10.0.0.2/32&reserved=1,2,3",
		"ssh://root:pw@11.11.11.11:22",
	}
	var nodes []node.Node
	for _, r := range raws {
		n, err := node.Parse(r)
		if err != nil {
			t.Fatal(r, err)
		}
		nodes = append(nodes, n)
	}
	b, skipped, err := BuildConfig(Spec{Nodes: nodes, Lines: []Line{{Port: 21080, NodeID: nodes[2].ID()}}, ClashAddr: "127.0.0.1:29090"})
	if err != nil || len(skipped) != 0 {
		t.Fatal(err, skipped)
	}
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, b, 0o600)
	if out, err := exec.Command(bin, "check", "-c", p).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check: %v\n%s", err, out)
	}
}

func TestHysteria2PinIsNotPassedAsPublicKeyHash(t *testing.T) {
	n, err := node.Parse("hysteria2://auth@7.7.7.7:443?pinSHA256=AA:BB:CC:DD&sni=a.com")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := BuildConfig(Spec{Nodes: []node.Node{n}, Lines: []Line{{Port: 1080, NodeID: n.ID()}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "certificate_public_key_sha256") {
		t.Fatal("pin нельзя передавать как certificate_public_key_sha256")
	}
}

func TestExtrasUotMuxJSON(t *testing.T) {
	n, _ := node.Parse("ss://YWVzLTI1Ni1nY206cHc=@1.1.1.1:8388")
	n.Extra = map[string]string{"uot": "1", "mux": "h2mux", "mux_padding": "1", "outbound_json": `{"tcp_fast_open":true,"tag":"hack"}`}
	b, skipped, err := BuildConfig(Spec{Nodes: []node.Node{n}, Lines: []Line{{Port: 1080, NodeID: n.ID()}}})
	if err != nil || len(skipped) != 0 {
		t.Fatal(err, skipped)
	}
	s := string(b)
	for _, want := range []string{`"udp_over_tcp": true`, `"protocol": "h2mux"`, `"padding": true`, `"tcp_fast_open": true`} {
		if !strings.Contains(s, want) {
			t.Errorf("нет %s", want)
		}
	}
	if strings.Contains(s, `"hack"`) {
		t.Error("тег переопределять нельзя")
	}
}

func TestRealSingboxCheckExtras(t *testing.T) {
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		t.Skip("SINGBOX_BIN не задан")
	}
	var nodes []node.Node
	for _, r := range []string{
		"ss://YWVzLTI1Ni1nY206cHc=@1.1.1.1:8388",
		"trojan://pw@3.3.3.3:443?sni=a.com",
		"vless://11111111-2222-3333-4444-555555555555@2.2.2.3:443?security=tls&sni=h.com",
	} {
		n, _ := node.Parse(r)
		n.Extra = map[string]string{"mux": "smux", "mux_padding": "1", "mux_max_streams": "8", "outbound_json": `{"tcp_fast_open":true}`}
		if n.Proto == node.SS {
			n.Extra["uot"] = "1"
		}
		nodes = append(nodes, n)
	}
	b, skipped, err := BuildConfig(Spec{Nodes: nodes, Lines: []Line{{Port: 21081, NodeID: nodes[0].ID()}}})
	if err != nil || len(skipped) != 0 {
		t.Fatal(err, skipped)
	}
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, b, 0o600)
	if out, err := exec.Command(bin, "check", "-c", p).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check: %v\n%s", err, out)
	}
}
