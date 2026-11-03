package ray2sing

import (
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

const (
	hWARPEndpointKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w=="
	hDeviceKey       = "MHcCAQEEIOAf/+45FJQE8VnQncfKBRVFDjKLtzKs/mcxkgCesLVjoAoGCCqGSM49AwEHoUQDQgAE5IFfZVGC9X0L5RMZz+Sn+pptLvCxKuRlCyAc+U6Z2G+xCtHQpCx53SJ7VkK8cM9Ul9r0kbOt+uEpC1rTHCVbQQ=="
)

func hEscape(v string) string { return strings.NewReplacer("+", "%2B", "=", "%3D").Replace(v) }

func hMasqueWARP(t *testing.T, link string) *T.WARPEndpointOptions {
	t.Helper()
	out, endpoint, err := MasqueLinkSingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil || endpoint == nil || endpoint.Type != C.TypeWARP {
		t.Fatalf("want a warp endpoint: %+v %+v", out, endpoint)
	}
	options := endpoint.Options.(*T.WARPEndpointOptions)
	if options.Mode != "masque" || options.MASQUE == nil || !options.MASQUE.Enabled {
		t.Fatalf("mode: %q %+v", options.Mode, options.MASQUE)
	}
	return options
}

// A masque:// link to WARP with its device key is a warp endpoint with mode masque that uses
// that device first; a masque outbound does not register a device when Cloudflare refuses it.
func TestMasqueWARPLinkWithKey(t *testing.T) {
	link := "masque://[2606:4700:103::2]:443?publicKey=" + hEscape(hWARPEndpointKey) + "&privateKey=" + hEscape(hDeviceKey) +
		"&ip=172.16.0.2&dns=1.1.1.1,%208.8.8.8&udp=1&cc=cubic&sni=www.deepseek.com&h2=1&flag=CDN#WARP-MASQUE"
	options := hMasqueWARP(t, link)
	device := options.MASQUE.Device
	if device == nil || device.PrivateKey != hDeviceKey || device.EndpointV6 != "[2606:4700:103::2]:443" || device.IPv4 != "172.16.0.2" {
		t.Fatalf("device: %+v", device)
	}
	if options.MASQUE.VHTTP != "h2" || options.MASQUE.ServerName != "www.deepseek.com" || options.MTU != 1280 {
		t.Fatalf("masque: %+v mtu %d", options.MASQUE, options.MTU)
	}
	if options.Server != "" || !strings.HasPrefix(options.UniqueIdentifier, "masque-") {
		t.Fatalf("server %q id %q", options.Server, options.UniqueIdentifier)
	}
	if again := hMasqueWARP(t, strings.Replace(link, "#WARP-MASQUE", "#renamed", 1)); again.UniqueIdentifier != options.UniqueIdentifier {
		t.Fatalf("renaming changed the identifier: %q %q", again.UniqueIdentifier, options.UniqueIdentifier)
	}
}

// Without a device key, the warp endpoint takes a saved device or registers one; the link
// failed with "private_key is not an ECDSA key".
func TestMasqueWARPLinkWithoutKey(t *testing.T) {
	options := hMasqueWARP(t, "masque://162.159.198.1:443?sni=consumer-masque.cloudflareclient.com&license=abc-123#keyless")
	if options.MASQUE.Device != nil || options.Profile.License != "abc-123" || !options.Scanner.Enabled || options.Server != "" {
		t.Fatalf("scanning: %+v", options)
	}
	// with the scanner off, the link's endpoint is the server
	options = hMasqueWARP(t, "masque://162.159.198.1:8095?sni=consumer-masque.cloudflareclient.com&scanner=0#keyless")
	if options.Server != "162.159.198.1" || options.ServerPort != 8095 {
		t.Fatalf("server: %q %d", options.Server, options.ServerPort)
	}
	// a device id names its devices; a host link a hash of its endpoint
	if options := hMasqueWARP(t, "masque://3f8a6c1e-device?endpoint=162.159.198.1:443#id"); options.UniqueIdentifier != "3f8a6c1e-device" {
		t.Fatalf("id: %q", options.UniqueIdentifier)
	}
	if options := hMasqueWARP(t, "masque://engage.cloudflareclient.com:2408?sni=masque.example.com#host"); !strings.HasPrefix(options.UniqueIdentifier, "masque-") {
		t.Fatalf("host: %q", options.UniqueIdentifier)
	}
}

// A link to another MASQUE server stays a masque outbound, and needs its device key.
func TestMasqueOtherServerLink(t *testing.T) {
	out, endpoint, err := MasqueLinkSingbox("masque://10.0.0.1:443?privateKey=" + hEscape(hDeviceKey) + "&sni=masque.example.com#mine")
	if err != nil || endpoint != nil || out == nil || out.Type != C.TypeMASQUE {
		t.Fatalf("%v %+v %+v", err, out, endpoint)
	}
	if _, _, err := MasqueLinkSingbox("masque://10.0.0.1:443?sni=masque.example.com#mine"); err == nil {
		t.Fatal("a link to another server without a key")
	}
}
