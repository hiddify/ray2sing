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

// The inner link of MASQUE in MASQUE runs through the outer one, without the scanner. Both are
// WARP, so both are warp endpoints with mode masque.
func TestMasqueInnerLink(t *testing.T) {
	link := testMasqueLink + "&inner=" + url.QueryEscape(strings.Replace(testMasqueLink, "60:443", "61:443", 1)) + "#Masque%20In%20Masque"
	options, err := Ray2SingboxOptions(context.Background(), link, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Endpoints) != 2 || len(options.Outbounds) != 0 {
		t.Fatalf("endpoints: %+v outbounds: %+v", options.Endpoints, options.Outbounds)
	}
	outer, inner := options.Endpoints[0], options.Endpoints[1]
	outerOptions, innerOptions := outer.Options.(*T.WARPEndpointOptions), inner.Options.(*T.WARPEndpointOptions)
	if outerOptions.MASQUE.Device.EndpointV4 != "162.159.198.60:443" || outerOptions.Detour != "" || !outerOptions.Scanner.Enabled {
		t.Fatalf("outer: %s %+v", outer.Tag, outerOptions)
	}
	if innerOptions.MASQUE.Device.EndpointV4 != "162.159.198.61:443" || innerOptions.Detour != outer.Tag || innerOptions.Scanner.Enabled {
		t.Fatalf("inner: %s %+v", inner.Tag, innerOptions)
	}
}

// MahsaNG writes the device's key before the "@" and the endpoint with its port after it, with
// no endpoint key; the link failed with "private_key is not an ECDSA key".
func TestMasqueKeyLink(t *testing.T) {
	const key = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgBwuLjlsggKUoQAHnXmQli6jPVuhju5hAV0io0Vt//H6gCgYIKoZIzj0DAQehRANCAAT9CueMifPPo9N28YF+og7UDN6iOwRMy1NVBxwy1fKZxus54nCwix5kIzj1pboJVgCmWBT7fCDLbQWsshNM/Gy1"
	link := "masque://" + url.QueryEscape(key) + "@162.159.198.2:8095?transport=h3&address=172.16.0.2%2F32,2606:4700:110:8a36::2%2F128&mtu=1280&remoteDNS=1.1.1.1&sni=consumer-masque.cloudflareclient.com&insecure=1&keepalive=5&wnoise=quic&wnoisecount=15&wnoisedelay=1-2&wpayloadsize=5-10#%D8%B2%D9%86+%D8%B2%D9%86%D8%AF%DA%AF%DB%8C"
	out, err := MasqueSingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	options := out.Options.(*T.MASQUEOutboundOptions)
	device := options.Device
	if out.Tag != "زن زندگی" || device.PrivateKey != key || device.EndpointPublicKey != "" || device.ID != "" {
		t.Fatalf("device: %q %+v", out.Tag, device)
	}
	if device.EndpointV4 != "162.159.198.2:8095" || device.EndpointV6 != "" || device.IPv4 != "172.16.0.2" || device.IPv6 != "2606:4700:110:8a36::2" {
		t.Fatalf("endpoints: %+v", device)
	}
	if options.VHTTP != "h3" || options.MTU != 1280 || options.UDPKeepalivePeriod != warpDuration("5") || !options.MASQUEOutboundTLSOptions.Insecure ||
		options.ServerName != "consumer-masque.cloudflareclient.com" {
		t.Fatalf("options: %+v", options)
	}

	// a raw key, insecure off, a pin, an IPv6 endpoint without a port, no address
	raw := "masque://" + key + "@[2606:4700:103::2]?transport=h2&insecure=0&pin=eb591b36ab26ba617e98371918c10bcdeae3742db6e76543f94be524dce1d555&packets=tlshello"
	out, err = MasqueSingbox(raw)
	if err != nil {
		t.Fatal(err)
	}
	options = out.Options.(*T.MASQUEOutboundOptions)
	device = options.Device
	if device.PrivateKey != key || device.EndpointV6 != "[2606:4700:103::2]:443" || device.EndpointV4 != "" || device.IPv4 != "172.16.0.2" {
		t.Fatalf("device: %+v", device)
	}
	tls := options.MASQUEOutboundTLSOptions
	if options.VHTTP != "h2" || tls.Insecure || !tls.Fragment || len(tls.CertificatePublicKeySHA256) != 1 || tls.CertificatePublicKeySHA256[0] != "eb591b36ab26ba617e98371918c10bcdeae3742db6e76543f94be524dce1d555" {
		t.Fatalf("options: %+v", options)
	}

	// the device-id shape keeps its key parameter and id
	out, err = MasqueSingbox(testMasqueLink)
	if err != nil {
		t.Fatal(err)
	}
	if device := out.Options.(*T.MASQUEOutboundOptions).Device; device.PrivateKey != "KEY-_" || device.ID != "9f880678-0ce1-47c9-a131-8a511ce60c1e" {
		t.Fatalf("device-id link: %+v", device)
	}
}

// Some apps write the endpoint as the host and the device's key as privateKey; the host was read
// as a device id, so the link had no endpoint and failed with "MASQUE device has no endpoint".
func TestMasqueHostEndpointLink(t *testing.T) {
	const key = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgBwuLjlsggKUoQAHnXmQli6jPVuhju5hAV0io0Vt//H6gCgYIKoZIzj0DAQehRANCAAT9CueMifPPo9N28YF+og7UDN6iOwRMy1NVBxwy1fKZxus54nCwix5kIzj1pboJVgCmWBT7fCDLbQWsshNM/Gy1"
	link := "masque://162.159.198.2:443?privateKey=" + strings.ReplaceAll(key, "+", "%2B") + "&ip=172.16.0.2/32&mtu=1280&keepalive=5&udp=1&sni=consumer-masque.cloudflareclient.com&flag=CDN#%D8%B2%D9%86+%D8%B2%D9%86%D8%AF%DA%AF%DB%8C%0A%3E"
	out, err := MasqueSingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	options := out.Options.(*T.MASQUEOutboundOptions)
	device := options.Device
	if out.Tag != "زن زندگی" || device.PrivateKey != key || device.ID != "" || options.UniqueIdentifier != "" {
		t.Fatalf("device: %q %+v", out.Tag, device)
	}
	if device.EndpointV4 != "162.159.198.2:443" || device.EndpointV6 != "" || device.IPv4 != "172.16.0.2" {
		t.Fatalf("endpoints: %+v", device)
	}
	if options.MTU != 1280 || options.UDPKeepalivePeriod != warpDuration("5") || options.ServerName != "consumer-masque.cloudflareclient.com" || options.MASQUEOutboundTLSOptions.Insecure {
		t.Fatalf("options: %+v", options)
	}

	// a domain host and an IPv6 host are endpoints too; a bare id stays an id
	for host, want := range map[string]string{"engage.cloudflareclient.com": "engage.cloudflareclient.com:443", "[2606:4700:103::2]": "[2606:4700:103::2]:443"} {
		out, err := MasqueSingbox("masque://" + host + "?privateKey=" + strings.ReplaceAll(key, "+", "%2B"))
		if err != nil {
			t.Fatal(err)
		}
		device := out.Options.(*T.MASQUEOutboundOptions).Device
		if got := device.EndpointV4 + device.EndpointV6; got != want || device.ID != "" {
			t.Fatalf("%s: %+v", host, device)
		}
	}
	out, err = MasqueSingbox("masque://3f8a6c1e-device?key=" + strings.ReplaceAll(key, "+", "%2B") + "&endpoint=162.159.198.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if device := out.Options.(*T.MASQUEOutboundOptions).Device; device.ID != "3f8a6c1e-device" || device.EndpointV4 != "162.159.198.1:443" {
		t.Fatalf("id link: %+v", device)
	}
}

// A link with h2=1 wants HTTP/2 only: without it, HTTP/3 (UDP), which filtering often blocks, was
// tried first on every connect. Its publicKey is the endpoint's key.
func TestMasqueHostEndpointLinkHTTP2(t *testing.T) {
	const peer = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w=="
	const key = "MHcCAQEEIOAf/+45FJQE8VnQncfKBRVFDjKLtzKs/mcxkgCesLVjoAoGCCqGSM49AwEHoUQDQgAE5IFfZVGC9X0L5RMZz+Sn+pptLvCxKuRlCyAc+U6Z2G+xCtHQpCx53SJ7VkK8cM9Ul9r0kbOt+uEpC1rTHCVbQQ=="
	escape := func(v string) string { return strings.NewReplacer("+", "%2B", "=", "%3D").Replace(v) }
	link := "masque://[2606:4700:103::2]:443?publicKey=" + escape(peer) + "&privateKey=" + escape(key) +
		"&ip=172.16.0.2&dns=1.1.1.1,%208.8.8.8&udp=1&cc=cubic&sni=www.deepseek.com&h2=1&flag=CDN#WARP-MASQUE"
	out, err := MasqueSingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	options := out.Options.(*T.MASQUEOutboundOptions)
	device := options.Device
	if device.PrivateKey != key || device.EndpointPublicKey != peer || device.EndpointV6 != "[2606:4700:103::2]:443" || device.IPv4 != "172.16.0.2" {
		t.Fatalf("device: %+v", device)
	}
	if options.VHTTP != "h2" || options.ServerName != "www.deepseek.com" || out.Tag != "WARP-MASQUE" {
		t.Fatalf("options: %q %q %q", options.VHTTP, options.ServerName, out.Tag)
	}
	// an explicit transport wins over h2
	out, err = MasqueSingbox(strings.Replace(link, "h2=1", "h2=1&transport=auto", 1))
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Options.(*T.MASQUEOutboundOptions).VHTTP; got != "auto" {
		t.Fatalf("transport=auto with h2=1: %q", got)
	}
}
