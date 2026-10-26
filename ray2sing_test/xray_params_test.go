package ray2sing_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/option"
)

func convertOne(t *testing.T, link string) option.Outbound {
	t.Helper()
	options, err := ray2sing.Ray2SingboxOptions(context.Background(), link, false)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(options.Outbounds) != 1 {
		t.Fatalf("expected one outbound, got %d", len(options.Outbounds))
	}
	return options.Outbounds[0]
}

const testUUID = "25da296e-1d96-48ae-9867-4342796cd742"

// VLESS encryption (mlkem768x25519plus...) is needed by flow=xtls-rprx-vision without TLS.
func TestVlessEncryption(t *testing.T) {
	vless := convertOne(t, "vless://"+testUUID+"@example.com:80?security=none&type=xhttp&path=%2Fp&flow=xtls-rprx-vision&encryption=mlkem768x25519plus.native.0rtt.c2VjcmV0#enc").Options.(*option.VLESSOutboundOptions)
	if vless.Encryption != "mlkem768x25519plus.native.0rtt.c2VjcmV0" {
		t.Fatalf("encryption not kept: %q", vless.Encryption)
	}
	plain := convertOne(t, "vless://"+testUUID+"@example.com:443?security=tls&sni=example.com&type=tcp&encryption=none#plain").Options.(*option.VLESSOutboundOptions)
	if plain.Encryption != "" {
		t.Fatalf("encryption=none must stay unset, got %q", plain.Encryption)
	}
}

// Xray raw TCP with the HTTP header stays HTTP/1.1 also over TLS (sing-box would use h2).
func TestRawHTTPHeaderOverTLS(t *testing.T) {
	check := func(name string, outbound option.Outbound, wantVersion int) {
		t.Helper()
		var transport *option.V2RayTransportOptions
		switch o := outbound.Options.(type) {
		case *option.VLESSOutboundOptions:
			transport = o.Transport
		case *option.VMessOutboundOptions:
			transport = o.Transport
		}
		if transport == nil || transport.Type != "http" {
			t.Fatalf("%s: expected http transport, got %+v", name, transport)
		}
		if transport.HTTPOptions.Version != wantVersion {
			t.Fatalf("%s: version = %d, want %d", name, transport.HTTPOptions.Version, wantVersion)
		}
		if wantVersion == 1 && transport.HTTPOptions.Method != "GET" {
			t.Fatalf("%s: method = %q, want GET", name, transport.HTTPOptions.Method)
		}
	}
	check("vless headerType=http over tls",
		convertOne(t, "vless://"+testUUID+"@example.com:443?security=tls&sni=example.com&type=tcp&headerType=http&path=%2Fp&host=example.com#raw"), 1)
	vmessJSON := `{"v":"2","add":"example.com","port":"443","id":"` + testUUID + `","aid":"0","net":"tcp","type":"http","host":"example.com","path":"/p","tls":"tls","sni":"example.com","ps":"raw"}`
	check("vmess net=tcp type=http over tls",
		convertOne(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(vmessJSON))), 1)
	// Xray's "http" network is HTTP/2: left to sing-box's default
	check("vless type=http (h2)",
		convertOne(t, "vless://"+testUUID+"@example.com:443?security=tls&sni=example.com&type=http&path=%2Fp&host=example.com#h2"), 0)
}

// Hiddify panel entries that only show usage/expiry are not servers
func TestSubscriptionInfoEntryIsSkipped(t *testing.T) {
	links := "trojan://1@20.59--2026.10.08.time:2059?sni=fake_ip_for_sub_link&security=tls#usage%20info\n" +
		"vless://" + testUUID + "@example.com:443?security=tls&sni=example.com&type=tcp#real"
	options, err := ray2sing.Ray2SingboxOptions(context.Background(), links, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Outbounds) != 1 || options.Outbounds[0].Type != "vless" {
		t.Fatalf("expected only the real server, got %d outbounds", len(options.Outbounds))
	}
}
