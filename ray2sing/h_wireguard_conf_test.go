package ray2sing

import (
	"context"
	"strings"
	"testing"

	T "github.com/sagernet/sing-box/option"
)

// WGTunnel confs pasted from a channel: the rule after a conf ended its last value
// ("PersistentKeepalive = 25───"), and "# Name" was not the tag.
func TestWireGuardConfNameAndRule(t *testing.T) {
	conf := "# Name = home\n[Interface]\nPrivateKey = a2V5\nAddress = 172.16.0.2/32\nJc = 6\nJmin = 56\nJmax = 160\n\n[Peer]\nPublicKey = cGVlcg==\nAllowedIPs = 0.0.0.0/0\nEndpoint = 8.6.112.10:2408\nPersistentKeepalive = 25"
	options, err := Ray2SingboxOptions(context.Background(), conf+"─────────────────\n"+strings.Replace(conf, "home", "second", 1), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Endpoints) != 2 {
		t.Fatalf("endpoints: %+v", options.Endpoints)
	}
	for i, name := range []string{"home", "second"} {
		endpoint := options.Endpoints[i]
		awg := endpoint.Options.(*T.AwgEndpointOptions)
		if !strings.HasPrefix(endpoint.Tag, name+" § ") || awg.Peers[0].PersistentKeepaliveInterval != 25 {
			t.Fatalf("%s: %+v", endpoint.Tag, awg.Peers)
		}
	}
}

// 3x-ui writes a randomised keepalive as a range: it was read as 0, which turns keepalive off.
func TestWireGuardKeepaliveRange(t *testing.T) {
	conf := "[Interface]\nPrivateKey = a2V5\nAddress = 172.16.0.2/32\n\n[Peer]\nPublicKey = cGVlcg==\nEndpoint = 8.6.112.10:2408\nPersistentKeepalive = 15-25"
	endpoint, err := AWGSingboxTxt(conf)
	if err != nil {
		t.Fatal(err)
	}
	if got := endpoint.Options.(*T.WireGuardEndpointOptions).Peers[0].PersistentKeepaliveInterval; got != 15 {
		t.Fatalf("conf keepalive %d", got)
	}
	endpoint, err = AWGSingbox("wireguard://a2V5@8.6.112.10:2408?publickey=cGVlcg%3D%3D&address=172.16.0.2/32&keepalive=15-25")
	if err != nil {
		t.Fatal(err)
	}
	var keepalive uint16
	switch options := endpoint.Options.(type) {
	case *T.WireGuardEndpointOptions:
		keepalive = options.Peers[0].PersistentKeepaliveInterval
	case *T.AwgEndpointOptions:
		keepalive = options.Peers[0].PersistentKeepaliveInterval
	}
	if keepalive != 15 {
		t.Fatalf("link keepalive %d", keepalive)
	}
	for value, want := range map[string]uint16{"25": 25, "off": 0, " 20 - 30 ": 20, "": 0} {
		if got := persistentKeepalive(value); got != want {
			t.Errorf("%q: %d, want %d", value, got, want)
		}
	}
}
