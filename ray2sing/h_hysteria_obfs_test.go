package ray2sing

import (
	"encoding/json"
	"testing"

	T "github.com/sagernet/sing-box/option"
)

// obfs=none means no obfuscation: the hysteria2 outbound kept it as an obfs type, which sing-box
// refuses to marshal, so the whole profile failed to import.
func TestHysteria2ObfsNone(t *testing.T) {
	for _, link := range []string{
		"hysteria2://pass@1.2.3.4:4433?obfs=none&peer=a.com",
		"hysteria2://pass@1.2.3.4:4433?obfs=&obfs-password=&sni=a.com",
	} {
		out, err := Hysteria2Singbox(link)
		if err != nil {
			t.Fatal(err)
		}
		if obfs := out.Options.(*T.Hysteria2OutboundOptions).Obfs; obfs != nil {
			t.Fatalf("%s: obfs %+v", link, obfs)
		}
		if _, err := json.Marshal(out); err != nil {
			t.Fatalf("%s: %v", link, err)
		}
	}
	out, err := Hysteria2Singbox("hysteria2://pass@1.2.3.4:4433?obfs=salamander&obfs-password=pw")
	if err != nil {
		t.Fatal(err)
	}
	if obfs := out.Options.(*T.Hysteria2OutboundOptions).Obfs; obfs == nil || obfs.Type != "salamander" || obfs.Password != "pw" {
		t.Fatalf("salamander obfs: %+v", obfs)
	}
}

// For hysteria (v1), obfs=none became the xplus password "none".
func TestHysteriaObfsNone(t *testing.T) {
	out, err := HysteriaSingbox("hysteria://1.2.3.4:7539?auth=a&obfs=none&protocol=udp&upmbps=50&downmbps=100")
	if err != nil {
		t.Fatal(err)
	}
	if obfs := out.Options.(*T.HysteriaOutboundOptions).Obfs; obfs != "" {
		t.Fatalf("obfs %q", obfs)
	}
}
