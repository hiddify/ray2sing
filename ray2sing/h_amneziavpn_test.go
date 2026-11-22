package ray2sing

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

// the client .conf 3x-ui 3.11 writes into an AmneziaWG subscription line (amneziaWGConfigText)
const threeXUIAmneziaConf = `[Interface]
PrivateKey = YCFDZBjSWnEhvRSdRNzNrbmgWCe1E8BDvlZ8D7Tq1VI=
Address = 10.66.66.2/32
DNS = 1.1.1.1, 1.0.0.1
MTU = 1380
Jc = 4
Jmin = 40
Jmax = 70
S1 = 52
S2 = 31
S3 = 18
S4 = 11
H1 = 100000-100100
H2 = 200000-200100
H3 = 300000-300100
H4 = 400000-400100
I1 = <b 0xc6000000>

# my-awg
[Peer]
PublicKey = oIy2yTUMUQ1jqAYC3kAVDEzm6fv6wX6SwXdvE1fYXzI=
PresharedKey = 0SlGrDsGQ2W3JOjcRY4H2tgXFzfIxOdk2xEwHYb5i+0=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.7:51820
PersistentKeepalive = 25`

// A 3x-ui subscription lists AmneziaWG as vpn://<base64url .conf>: it was dropped as an
// unsupported link, and only the other configs were imported (hiddify-app#2642).
func TestAmneziaVPNLinkFrom3xUISubscription(t *testing.T) {
	sub := strings.Join([]string{
		"vless://3c8f0a4e-8a3b-4c55-9d0a-1d8e3b0f1a22@203.0.113.7:443?type=tcp&security=none#vless",
		"vpn://" + base64.RawURLEncoding.EncodeToString([]byte(threeXUIAmneziaConf)),
		"hysteria2://pass@203.0.113.7:8443?sni=example.com#hy2",
	}, "\n")
	options, err := Ray2SingboxOptions(context.Background(), base64.StdEncoding.EncodeToString([]byte(sub)), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Endpoints) != 1 {
		t.Fatalf("endpoints: %+v", options.Endpoints)
	}
	endpoint := options.Endpoints[0]
	if endpoint.Type != C.TypeAwg || !strings.HasPrefix(endpoint.Tag, "my-awg § ") {
		t.Fatalf("endpoint %s %q", endpoint.Type, endpoint.Tag)
	}
	awg := endpoint.Options.(*T.AwgEndpointOptions)
	if awg.MTU != 1380 || awg.Awg.Jc != 4 || awg.Awg.S3 != 18 || awg.Awg.S4 != 11 ||
		awg.Awg.H1 != "100000-100100" || awg.Awg.I1 != "<b 0xc6000000>" {
		t.Fatalf("awg: %+v", awg)
	}
	peer := awg.Peers[0]
	if peer.Address != "203.0.113.7" || peer.Port != 51820 || peer.PresharedKey == "" || peer.PersistentKeepaliveInterval != 25 {
		t.Fatalf("peer: %+v", peer)
	}
}

// AmneziaVPN's own vpn:// link: qCompress'd JSON whose AmneziaWG container holds the .conf.
func TestAmneziaVPNLinkFromAmneziaVPN(t *testing.T) {
	lastConfig, _ := json.Marshal(map[string]string{"config": threeXUIAmneziaConf})
	server, _ := json.Marshal(map[string]any{
		"containers": []any{
			map[string]any{"container": "amnezia-xray", "xray": map[string]any{"last_config": `{"inbounds":[]}`}},
			map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": string(lastConfig)}},
		},
		"defaultContainer": "amnezia-awg",
		"description":      "Home server",
	})
	var compressed bytes.Buffer
	_ = binary.Write(&compressed, binary.BigEndian, uint32(len(server)))
	writer := zlib.NewWriter(&compressed)
	writer.Write(server)
	writer.Close()

	options, err := Ray2SingboxOptions(context.Background(), "vpn://"+base64.RawURLEncoding.EncodeToString(compressed.Bytes()), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Endpoints) != 1 || !strings.HasPrefix(options.Endpoints[0].Tag, "Home server § ") {
		t.Fatalf("endpoints: %+v", options.Endpoints)
	}

	// a link that carries no client config, such as AmneziaVPN's full server access, is an error
	if _, err := AmneziaVPNSingbox("vpn://" + base64.RawURLEncoding.EncodeToString([]byte(`{"containers":[],"hostName":"x"}`))); err == nil {
		t.Fatal("no error for a config without a client config")
	}
}
