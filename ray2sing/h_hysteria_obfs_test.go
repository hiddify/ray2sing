package ray2sing

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/sagernet/sing-box/include"

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

// Xray hysteria2 links put salamander both in obfs= and in the fm udp finalmask: it is one layer,
// applied once by the dialer mask, not also by the outbound's own obfs.
func TestHysteria2XrayFinalMask(t *testing.T) {
	link := "hysteria2://040de430-63fd-46e7-b781-6b8b1e094a0e@1.2.3.4:995/?obfs=salamander&obfs-password=IaFMLSj3eXhDGFxMbXwnSw%3D%3D&sni=edge.example.com&fm=%7B%22udp%22%3A%5B%7B%22type%22%3A%22salamander%22%2C%22settings%22%3A%7B%22password%22%3A%22IaFMLSj3eXhDGFxMbXwnSw%3D%3D%22%7D%7D%5D%2C%22quicParams%22%3A%7B%22congestion%22%3A%22brutal%22%7D%7D#name"
	options, err := Ray2SingboxOptions(include.Context(context.Background()), link, false)
	if err != nil {
		t.Fatal(err)
	}
	opts := options.Outbounds[0].Options.(*T.Hysteria2OutboundOptions)
	if opts.Obfs != nil {
		t.Fatalf("obfs kept beside the fm salamander: %+v", opts.Obfs)
	}
	if fm := opts.FinalMask; fm == nil || len(fm.UDP) != 1 || fm.UDP[0].Type != "salamander" {
		t.Fatalf("finalmask: %+v", fm)
	}
	if opts.UpMbps != 0 || opts.DownMbps != 0 {
		t.Fatalf("brutal without bandwidth set up %d down %d", opts.UpMbps, opts.DownMbps)
	}
}

func TestHysteria2XrayQuicParams(t *testing.T) {
	fm := url.QueryEscape(`{"quicParams":{"congestion":"brutal","brutalUp":"50 mbps","brutalDown":"100 mbps","bbrProfile":"Aggressive","maxIdleTimeout":30,"keepAlivePeriod":10}}`)
	out, err := Hysteria2Singbox("hysteria2://pw@1.2.3.4:443?obfs=salamander&obfs-password=x&fm=" + fm)
	if err != nil {
		t.Fatal(err)
	}
	opts := out.Options.(*T.Hysteria2OutboundOptions)
	// no udp salamander in fm: the outbound keeps its own obfs
	if opts.Obfs == nil || opts.Obfs.Type != "salamander" {
		t.Fatalf("obfs: %+v", opts.Obfs)
	}
	// Xray mbps is 2^20 bits: 50 -> 52, 100 -> 105 sing-box Mbps
	if opts.UpMbps != 52 || opts.DownMbps != 105 || opts.BBRProfile != "aggressive" {
		t.Fatalf("up %d down %d bbr %q", opts.UpMbps, opts.DownMbps, opts.BBRProfile)
	}
	if time.Duration(opts.IdleTimeout) != 30*time.Second || time.Duration(opts.KeepAlivePeriod) != 10*time.Second {
		t.Fatalf("idle %v keepalive %v", opts.IdleTimeout, opts.KeepAlivePeriod)
	}
	out, err = Hysteria2Singbox("hysteria2://pw@1.2.3.4:443?fm=" + url.QueryEscape(`{"quicParams":{"congestion":"bbr","brutalUp":"50 mbps"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if up := out.Options.(*T.Hysteria2OutboundOptions).UpMbps; up != 0 {
		t.Fatalf("bbr congestion set up %d", up)
	}
}
