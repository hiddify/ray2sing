package ray2sing

import (
	"testing"

	"github.com/sagernet/wireguard-go/hiddify"
)

// Xray WARP links: wnoise=random is plain random bytes, wnoise=quic QUIC Initials. Both were mapped
// to a mode the WireGuard device does not know, so it sent random packets after a header.
func TestWireGuardXrayNoise(t *testing.T) {
	random := getWireGuardNoise(map[string]string{"wnoise": "random", "wnoisecount": "5", "wpayloadsize": "5-10", "wnoisedelay": "2-5"}, false)
	fake := random.FakePacket
	if !fake.Enabled || fake.Mode != hiddify.NoiseModeRaw || fake.Count != (hiddify.Range{From: 5, To: 5}) || fake.Size != (hiddify.Range{From: 5, To: 10}) || fake.Delay != (hiddify.Range{From: 2, To: 5}) {
		t.Fatalf("wnoise=random: %+v", fake)
	}
	quic := getWireGuardNoise(map[string]string{"wnoise": "quic", "wnoisecount": "2-4"}, false)
	if quic.FakePacket.Mode != hiddify.NoiseModeQUIC {
		t.Fatalf("wnoise=quic: %+v", quic.FakePacket)
	}
	if mode := defaultWireguardNoiseOptions().FakePacket.Mode; mode != "" {
		t.Fatalf("default noise mode %q is not a mode", mode)
	}
}
