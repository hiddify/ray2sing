package ray2sing_test

import (
	"strings"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/option"
)

// A WireGuard .conf with comment lines inside its sections (as exported by Proton VPN).
const wgConfWithComments = `[Interface]
# Bouncing = 0
# NAT-PMP (Port Forwarding) = off
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=
Address = 10.2.0.2/32, 2001:db8::2/128
DNS = 10.2.0.1

[Peer]
# NL-FREE#1
PublicKey = cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViMDA=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 198.51.100.1:51820

# Endpoint = [2001:db8::10]:51820
PersistentKeepalive = 25
`

func TestWireGuardConfWithComments(t *testing.T) {
	options, err := ray2sing.Ray2SingboxOptions(t.Context(), wgConfWithComments, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Endpoints) != 1 {
		t.Fatalf("got %d endpoints, want 1", len(options.Endpoints))
	}
	endpoint := options.Endpoints[0]
	var privateKey string
	var peers int
	var address string
	var port uint16
	switch opts := endpoint.Options.(type) {
	case *option.AwgEndpointOptions:
		privateKey, peers = opts.PrivateKey, len(opts.Peers)
		if peers > 0 {
			address, port = opts.Peers[0].Address, opts.Peers[0].Port
		}
	case *option.WireGuardEndpointOptions:
		privateKey, peers = opts.PrivateKey, len(opts.Peers)
		if peers > 0 {
			address, port = opts.Peers[0].Address, opts.Peers[0].Port
		}
	default:
		t.Fatalf("unexpected endpoint options %T", endpoint.Options)
	}
	if privateKey != "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=" {
		t.Fatalf("private key not parsed: %q", privateKey)
	}
	if peers != 1 || address != "198.51.100.1" || port != 51820 {
		t.Fatalf("peer not parsed: peers=%d address=%q port=%d", peers, address, port)
	}
}

func TestMultipleConfigsSeparatedByEquals(t *testing.T) {
	second := strings.ReplaceAll(wgConfWithComments, "198.51.100.1", "198.51.100.2")
	input := wgConfWithComments + "\n===\n" + second + "\n  ====  \r\nsocks://dXNlcjpwYXNz@203.0.113.1:1080#socks\n"
	testMultipleConfigs(t, input)
	// "#===" is a separator too, and reads as a comment to other tools
	testMultipleConfigs(t, wgConfWithComments+"\n#===\n"+second+"\n# ===\nsocks://dXNlcjpwYXNz@203.0.113.1:1080#socks\n")
}

func testMultipleConfigs(t *testing.T, input string) {
	t.Helper()
	second := "198.51.100.2"
	options, err := ray2sing.Ray2SingboxOptions(t.Context(), input, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Endpoints) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(options.Endpoints))
	}
	if len(options.Outbounds) != 1 || options.Outbounds[0].Type != "socks" {
		t.Fatalf("got outbounds %+v, want one socks outbound", options.Outbounds)
	}
	for i, want := range []string{"198.51.100.1", second} {
		var address string
		switch opts := options.Endpoints[i].Options.(type) {
		case *option.AwgEndpointOptions:
			address = opts.Peers[0].Address
		case *option.WireGuardEndpointOptions:
			address = opts.Peers[0].Address
		}
		if address != want {
			t.Fatalf("endpoint %d peer address %q, want %q", i, address, want)
		}
	}
}
