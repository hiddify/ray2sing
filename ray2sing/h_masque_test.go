package ray2sing

import (
	"context"
	"net/url"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

const testMasqueLink = "masque://9f880678-0ce1-47c9-a131-8a511ce60c1e?key=KEY-_&peer=PEER-_&addr=172.16.0.2&endpoint6=[2606:4700:103::2]:443&transport=h2&endpoint=162.159.198.60:443&split=sni&junk=firewall&sni=www.cloudflare.com&framing=h3&cfdef=162.159.198.2:443"

// masque:// links were not read: "unable to determine config format".
func TestMasqueLink(t *testing.T) {
	out, err := MasqueSingbox(testMasqueLink + "#Masque")
	if err != nil {
		t.Fatal(err)
	}
	options := out.Options.(*T.MASQUEOutboundOptions)
	device := options.Device
	if out.Type != C.TypeMASQUE || out.Tag != "Masque" || device == nil || device.PrivateKey != "KEY-_" || device.EndpointPublicKey != "PEER-_" ||
		device.ID != "9f880678-0ce1-47c9-a131-8a511ce60c1e" || device.IPv4 != "172.16.0.2" {
		t.Fatalf("device: %+v", device)
	}
	if device.EndpointV4 != "162.159.198.60:443" || device.EndpointV6 != "[2606:4700:103::2]:443" || device.EndpointH2V4 != "162.159.198.2:443" {
		t.Fatalf("endpoints: %+v", device)
	}
	if options.VHTTP != "h2" || options.ServerName != "www.cloudflare.com" || !options.MASQUEOutboundTLSOptions.Fragment || !options.Scanner.Enabled {
		t.Fatalf("options: %+v", options)
	}
}

// The inner link of MASQUE in MASQUE runs through the outer one, without the scanner.
func TestMasqueInnerLink(t *testing.T) {
	link := testMasqueLink + "&inner=" + url.QueryEscape(strings.Replace(testMasqueLink, "60:443", "61:443", 1)) + "#Masque%20In%20Masque"
	options, err := Ray2SingboxOptions(context.Background(), link, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Outbounds) != 2 {
		t.Fatalf("outbounds: %+v", options.Outbounds)
	}
	outer, inner := options.Outbounds[0], options.Outbounds[1]
	outerOptions, innerOptions := outer.Options.(*T.MASQUEOutboundOptions), inner.Options.(*T.MASQUEOutboundOptions)
	if outerOptions.Device.EndpointV4 != "162.159.198.60:443" || outerOptions.Detour != "" || !outerOptions.Scanner.Enabled {
		t.Fatalf("outer: %s %+v", outer.Tag, outerOptions)
	}
	if innerOptions.Device.EndpointV4 != "162.159.198.61:443" || innerOptions.Detour != outer.Tag || innerOptions.Scanner.Enabled {
		t.Fatalf("inner: %s %+v", inner.Tag, innerOptions)
	}
}
