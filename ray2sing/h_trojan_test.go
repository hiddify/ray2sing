package ray2sing

import (
	"net/url"
	"testing"

	T "github.com/sagernet/sing-box/option"
)

// Trojan links with security=reality lost the REALITY options, so the client did a plain TLS
// handshake with the camouflage site.
func TestTrojanReality(t *testing.T) {
	out, err := TrojanSingbox("trojan://pass@1.2.3.4:443?security=reality&sni=z.com&fp=chrome&pbk=PUBKEY&sid=1bf7&type=grpc&serviceName=svc#name")
	if err != nil {
		t.Fatal(err)
	}
	tls := out.Options.(*T.TrojanOutboundOptions).TLS
	if tls == nil || tls.Reality == nil || !tls.Reality.Enabled || tls.Reality.PublicKey != "PUBKEY" || tls.Reality.ShortID != "1bf7" {
		t.Fatalf("reality options: %+v", tls)
	}
}

// The httpupgrade host was put in headers, which Go does not send: a CDN reached by IP saw the IP as Host.
func TestHTTPUpgradeHost(t *testing.T) {
	out, err := VlessSingbox("vless://uuid@104.16.135.43:80?security=none&type=httpupgrade&path=%2Fp&host=cdn.example.com#name")
	if err != nil {
		t.Fatal(err)
	}
	transport := out.Options.(*T.VLESSOutboundOptions).Transport
	if transport == nil || transport.HTTPUpgradeOptions.Host != "cdn.example.com" {
		t.Fatalf("httpupgrade transport: %+v", transport)
	}
}

// Raw TCP with the HTTP header sends Xray's browser headers: a request shorter than Xray's first
// read behind a PROXY protocol hop made its Trojan inbound reject the connection.
func TestRawHTTPHeaders(t *testing.T) {
	out, err := TrojanSingbox("trojan://pass@1.2.3.4:443?security=tls&sni=a.com&type=tcp&headerType=http&path=%2Fp&host=a.com#name")
	if err != nil {
		t.Fatal(err)
	}
	transport := out.Options.(*T.TrojanOutboundOptions).Transport
	if transport == nil || transport.HTTPOptions.Version != 1 || len(transport.HTTPOptions.Headers["Accept-Encoding"]) == 0 {
		t.Fatalf("raw HTTP transport: %+v", transport)
	}
}

// keyshare=classical drops X25519MLKEM768 from the REALITY ClientHello: some DPI blocks the
// two-segment hybrid ClientHello (hiddify-app#2439).
func TestRealityKeyShare(t *testing.T) {
	out, err := VlessSingbox("vless://uuid@1.2.3.4:443?security=reality&sni=z.com&fp=chrome&pbk=PUBKEY&sid=1bf7&type=tcp&keyshare=Classical#name")
	if err != nil {
		t.Fatal(err)
	}
	if tls := out.Options.(*T.VLESSOutboundOptions).TLS; tls == nil || tls.Reality == nil || tls.Reality.KeyShare != "classical" {
		t.Fatalf("reality options: %+v", tls)
	}
	out, err = TrojanSingbox("trojan://pass@1.2.3.4:443?security=reality&sni=z.com&fp=chrome&pbk=PUBKEY&key_share=hybrid#name")
	if err != nil {
		t.Fatal(err)
	}
	if tls := out.Options.(*T.TrojanOutboundOptions).TLS; tls == nil || tls.Reality == nil || tls.Reality.KeyShare != "hybrid" {
		t.Fatalf("reality options: %+v", tls)
	}
}

// The xhttp download leg takes keyShare from its realitySettings, else the link's keyshare.
func TestRealityKeyShareXHTTPDownload(t *testing.T) {
	for _, test := range []struct{ dlKeyShare, want string }{{"", "classical"}, {`,"keyShare":"hybrid"`, "hybrid"}} {
		extra := url.QueryEscape(`{"downloadSettings":{"address":"5.6.7.8","port":443,"security":"reality","realitySettings":{"publicKey":"DLKEY","serverName":"d.com","fingerprint":"chrome"` + test.dlKeyShare + `}}}`)
		out, err := VlessSingbox("vless://uuid@1.2.3.4:443?security=reality&sni=z.com&fp=chrome&pbk=PUBKEY&type=xhttp&path=%2Fp&keyshare=classical&extra=" + extra + "#name")
		if err != nil {
			t.Fatal(err)
		}
		download := out.Options.(*T.VLESSOutboundOptions).Transport.XHTTPOptions.Download
		if download == nil || download.TLS == nil || download.TLS.Reality == nil || download.TLS.Reality.KeyShare != test.want {
			t.Fatalf("download %q: %+v", test.dlKeyShare, download)
		}
	}
}
