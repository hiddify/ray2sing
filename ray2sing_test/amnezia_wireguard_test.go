package ray2sing_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
)

const testPrivateKey = "cGsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
const testPublicKey = "cHViAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func convert(t *testing.T, config string) string {
	t.Helper()
	out, err := ray2sing.Ray2Singbox(libbox.BaseContext(nil), config, false)
	if err != nil {
		t.Fatalf("%v\n%s", err, config)
	}
	return string(out)
}

func wantAll(t *testing.T, got string, fields ...string) {
	t.Helper()
	got = strings.NewReplacer(`\u003c`, "<", `\u003e`, ">").Replace(got)
	for _, field := range fields {
		if !strings.Contains(got, field) {
			t.Errorf("missing %s in\n%s", field, got)
		}
	}
}

// The AmneziaWG values of a wg:// link come in obfsParam, a JSON object (Karing and other sing-box
// based clients); a bare address is that one address.
func TestWgLinkObfsParam(t *testing.T) {
	got := convert(t, "wg://[2001:db8::1]:988?publicKey="+strings.ReplaceAll(testPublicKey, "=", "%3D")+
		"&privateKey="+strings.ReplaceAll(testPrivateKey, "=", "%3D")+"&ip=172.16.0.2,2001:db8:110::2&mtu=1280&dns=8.8.8.8&udp=1"+
		"&obfs=amneziawg&obfsParam=%7B%22s3%22:%220%22,%22h1%22:%221%22,%22i2%22:%22%3Cr%202%3E%3Cb%200x0100%3E%22,%22jmax%22:%22220%22,"+
		"%22h2%22:%222%22,%22s4%22:%220%22,%22jmin%22:%2280%22,%22h3%22:%223%22,%22s1%22:%220%22,%22jc%22:%226%22,%22h4%22:%224%22,"+
		"%22s2%22:%220%22,%22i1%22:%22%3Cr%202%3E%3Cb%200x0001%3E%22%7D&flag=CDN")
	wantAll(t, got, `"type":"awg"`, `"address":["172.16.0.2/32","2001:db8:110::2/128"]`,
		`"jc":6`, `"jmin":80`, `"jmax":220`, `"h1":"1"`, `"h4":"4"`, `"i1":"<r 2><b 0x0001>"`, `"i2":"<r 2><b 0x0100>"`)
}

// AmneziaWG values that a plain WireGuard server accepts (s 0, h 1–4), with the peer's reserved
// bytes (WARP): a WireGuard endpoint that sends the same packets as noise, keeping reserved.
func TestAwgConfWithReservedAsNoise(t *testing.T) {
	got := convert(t, `[Interface]
PrivateKey = `+testPrivateKey+`
Address = 172.16.0.2/32
Jc = 5
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <r 2><b 0x0100>
I2 = <b 0x5cf9><r 38>

[Peer]
PublicKey = `+testPublicKey+`
Endpoint = 192.0.2.1:4500
Reserved = 124, 245, 25
`)
	wantAll(t, got, `"type":"wireguard"`, `"reserved":"fPUZ"`, `"count":"5-5"`, `"size":"40-70"`, `"mode":"raw"`,
		`"packets":["<r 2><b 0x0100>","<b 0x5cf9><r 38>"]`)
}

// Values a WireGuard server does not accept, or a tag noise cannot build, keep the awg endpoint;
// it keeps the reserved bytes when its messages have room for them.
func TestAwgNotWireGuardCompatibleStaysAwg(t *testing.T) {
	for name, values := range map[string]string{
		"s1":  "S1 = 15\nH1 = 1",
		"h1":  "H1 = 5",
		"tag": "I1 = <d>",
	} {
		got := convert(t, "[Interface]\nPrivateKey = "+testPrivateKey+"\nAddress = 172.16.0.2/32\nJc = 3\nJmin = 10\nJmax = 20\n"+values+
			"\n\n[Peer]\nPublicKey = "+testPublicKey+"\nEndpoint = 192.0.2.1:4500\nReserved = 1,2,3\n")
		if !strings.Contains(got, `"type":"awg"`) {
			t.Errorf("%s: want awg in\n%s", name, got)
		}
		if keeps := strings.Contains(got, `"reserved":"AQID"`); keeps != (name != "s1") {
			t.Errorf("%s: reserved kept %v in\n%s", name, keeps, got)
		}
	}
}

// sing-box-lx writes the AmneziaWG values next to the WireGuard endpoint's own fields.
func TestMoveAmneziaWireGuardFields(t *testing.T) {
	var endpoints []any
	json.Unmarshal([]byte(`[
		{"type":"wireguard","tag":"warp","private_key":"k","address":["172.16.0.2/32"],
		 "peers":[{"address":"192.0.2.1","port":2408,"public_key":"p","reserved":[154,214,128]}],
		 "jc":8,"jmin":64,"jmax":231,"s1":0,"s2":0,"h1":1,"h2":2,"h3":3,"h4":4,"id":"www.google.com","ip":"quic","ib":"chrome"},
		{"type":"wireguard","tag":"awg","private_key":"k","address":["10.0.0.2/32"],"workers":2,
		 "peers":[{"address":"192.0.2.2","port":51820,"public_key":"p","pre_shared_key":"s","reserved":[1,2,3]}],
		 "jc":4,"jmin":40,"jmax":70,"s1":15,"s2":18,"h1":"1111","h2":"2222","h3":"3333","h4":"4444"},
		{"type":"wireguard","tag":"awg-reserved","private_key":"k","address":["10.0.0.4/32"],
		 "peers":[{"address":"192.0.2.4","port":51820,"public_key":"p","reserved":[7,8,9]}],
		 "jc":4,"jmin":40,"jmax":70,"h1":5,"h2":6,"h3":7,"h4":8},
		{"type":"wireguard","tag":"plain","private_key":"k","address":["10.0.0.3/32"],"peers":[{"address":"192.0.2.3","port":51820,"public_key":"p"}]}
	]`), &endpoints)
	out, _ := json.Marshal(ray2sing.MoveAmneziaWireGuardFields(endpoints))
	got := string(out)
	wantAll(t, got,
		`"noise":{"fake_packet":{"count":"8-8","delay":"","enabled":true,"mode":"raw","packets":["<qi www.google.com>"],"size":"64-231"}}`,
		`"type":"awg"`, `"awg":{"h1":"1111","h2":"2222","h3":"3333","h4":"4444","jc":4,"jmax":70,"jmin":40,"s1":15,"s2":18}`,
		`"preshared_key":"s"`, `"allowed_ips":["0.0.0.0/0","::/0"]`,
		`"awg":{"h1":"5","h2":"6","h3":"7","h4":"8","jc":4,"jmax":70,"jmin":40},"peers":[{"address":"192.0.2.4","allowed_ips":["0.0.0.0/0","::/0"],"port":51820,"public_key":"p","reserved":[7,8,9]}]`)
	got = strings.NewReplacer(`\u003c`, "<", `\u003e`, ">").Replace(got)
	for _, gone := range []string{`"jc":8`, `"ib"`, `"workers"`, `"pre_shared_key"`, `"reserved":[1,2,3]`} {
		if strings.Contains(got, gone) {
			t.Errorf("%s left in\n%s", gone, got)
		}
	}
}
