package ray2sing_test

import (
	"reflect"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestLegacyWireGuardOutboundToEndpoint(t *testing.T) {
	legacy := map[string]any{
		"type": "wireguard", "tag": "wg", "server": "198.51.100.1", "server_port": float64(51820),
		"local_address": "10.0.0.2/32", "private_key": "priv", "peer_public_key": "pub",
		"pre_shared_key": "psk", "reserved": []any{float64(1), float64(2), float64(3)}, "mtu": float64(1380),
		"detour": "select", "gso": true,
	}
	endpoint, ok := ray2sing.LegacyWireGuardOutboundToEndpoint(legacy)
	if !ok {
		t.Fatal("not converted")
	}
	want := map[string]any{
		"type": "wireguard", "tag": "wg", "address": []any{"10.0.0.2/32"}, "private_key": "priv",
		"mtu": float64(1380), "detour": "select",
		"peers": []any{map[string]any{
			"address": "198.51.100.1", "port": float64(51820), "public_key": "pub", "pre_shared_key": "psk",
			"reserved": []any{float64(1), float64(2), float64(3)}, "allowed_ips": []any{"0.0.0.0/0", "::/0"},
		}},
	}
	if !reflect.DeepEqual(endpoint, want) {
		t.Fatalf("got %#v\nwant %#v", endpoint, want)
	}

	// an endpoint-format wireguard and other outbounds are left alone
	if _, ok := ray2sing.LegacyWireGuardOutboundToEndpoint(map[string]any{"type": "wireguard", "address": []any{"10.0.0.2/32"}}); ok {
		t.Fatal("new format converted")
	}
	outbounds, endpoints := ray2sing.MoveLegacyWireGuardOutbounds(
		[]any{map[string]any{"type": "vless", "tag": "v"}, legacy},
		[]any{map[string]any{"type": "wireguard", "tag": "existing"}},
	)
	if len(outbounds) != 1 || len(endpoints) != 2 || endpoints[1].(map[string]any)["tag"] != "wg" {
		t.Fatalf("outbounds %v endpoints %v", outbounds, endpoints)
	}
}
