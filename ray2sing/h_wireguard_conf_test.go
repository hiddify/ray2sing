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
