package ray2sing

import (
	"context"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func warpOptions(t *testing.T, link string) *T.WARPEndpointOptions {
	t.Helper()
	out, err := WarpSingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	return out.Options.(*T.WARPEndpointOptions)
}

// A link without a mode ran plain WireGuard: it is auto, with the scanner and the noise search on.
func TestWarpDefaults(t *testing.T) {
	options := warpOptions(t, "warp://B2@auto?ifpm=m4#LocalIP")
	if options.Mode != "auto" || options.Server != "" || options.AWG != nil || options.MASQUE != nil {
		t.Fatalf("defaults: mode %q server %q awg %+v masque %+v", options.Mode, options.Server, options.AWG, options.MASQUE)
	}
	if options.Scanner == nil || !options.Scanner.Enabled || !options.Scanner.SearchNoise {
		t.Fatalf("scanner: %+v", options.Scanner)
	}
	if options.Noise.FakePacket.Mode != "m4" {
		t.Fatalf("noise: %+v", options.Noise)
	}
}

func TestWarpExplicitOptions(t *testing.T) {
	options := warpOptions(t, "warp://p1@162.159.192.1:2408?mode=masque&vhttp=h2&masque_sni=a.com&udp_keepalive_period=30&scanner=0&search_noise=false&scan_ports=500,2408&noise_presets=quic,dns&mtu=1330&license=K")
	if options.Mode != "masque" || options.Server != "162.159.192.1" || options.ServerPort != 2408 || options.MTU != 1330 || options.Profile.License != "K" {
		t.Fatalf("options: %+v", options)
	}
	if options.MASQUE == nil || options.MASQUE.VHTTP != "h2" || options.MASQUE.ServerName != "a.com" || time.Duration(options.MASQUE.UDPKeepalivePeriod) != 30*time.Second {
		t.Fatalf("masque: %+v", options.MASQUE)
	}
	scanner := options.Scanner
	if scanner.Enabled || scanner.SearchNoise || len(scanner.Ports) != 2 || len(scanner.NoisePresets) != 2 || scanner.NoisePresets[1] != "dns-google" {
		t.Fatalf("scanner: %+v", scanner)
	}
	for _, mode := range []string{"wg", "awg", "auto"} {
		if got := warpOptions(t, "warp://p1@auto?mode="+mode).Mode; got != mode {
			t.Fatalf("mode %s: %s", mode, got)
		}
	}
}

// A noise preset sets the WireGuard noise and, without AmneziaWG fields, the AmneziaWG junk.
func TestWarpNoisePreset(t *testing.T) {
	options := warpOptions(t, "warp://p1@auto?ifpm=dns&ifpd=5-10")
	fake := options.Noise.FakePacket
	if !fake.Enabled || len(fake.Packets) != 3 || fake.Delay.To != 10 || fake.Count.To != 6 {
		t.Fatalf("noise: %+v", fake)
	}
	if options.AWG == nil || options.AWG.I1 == "" || options.AWG.Jc != 6 {
		t.Fatalf("awg: %+v", options.AWG)
	}
	options = warpOptions(t, "warp://p1@auto?mode=awg&jc=4&jmin=40&jmax=70&rekey_after_time=60-120&random_trailers=1")
	if options.AWG == nil || options.AWG.Jc != 4 || options.AWG.RekeyAfterTime != "60-120" || !options.AWG.RandomTrailers {
		t.Fatalf("awg: %+v", options.AWG)
	}
}

// Behind a detour the scanner would probe through the detour: it is off for the inner hop.
func TestWarpScannerOffBehindDetour(t *testing.T) {
	options, err := Ray2SingboxOptions(context.Background(), "warp://B1@auto#WarpInWarp -> warp://B2@auto?ifpm=m4#LocalIP", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range options.Endpoints {
		if endpoint.Type != C.TypeWARP {
			continue
		}
		warp := endpoint.Options.(*T.WARPEndpointOptions)
		behindDetour := warp.Detour != ""
		if warp.Scanner.Enabled == behindDetour || warp.Scanner.SearchNoise == behindDetour {
			t.Fatalf("%s (detour %q): scanner %+v", endpoint.Tag, warp.Detour, warp.Scanner)
		}
	}
}
