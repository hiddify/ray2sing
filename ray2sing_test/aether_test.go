package ray2sing_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func parseAether(t *testing.T, link string) *T.Options {
	t.Helper()
	options, err := ray2sing.Ray2SingboxOptions(context.Background(), link, false)
	if err != nil {
		t.Fatal(err)
	}
	return options
}

func warpOf(t *testing.T, endpoint T.Endpoint) *T.WARPEndpointOptions {
	t.Helper()
	if endpoint.Type != C.TypeWARP {
		t.Fatalf("not a warp endpoint: %+v", endpoint)
	}
	return endpoint.Options.(*T.WARPEndpointOptions)
}

// WireGuard over MASQUE: the WireGuard hop runs through the MASQUE one, which is at the link's outer
// endpoint over HTTP/2 with Aether's server name.
func TestAetherWgOverMasque(t *testing.T) {
	options := parseAether(t, "aether://?protocol=wg-over-masque&scan=balanced&ip=v4&transport=h2&outer=1.1.1.1%3A443#Not%20YouTube%20")
	if len(options.Endpoints) != 2 || len(options.Outbounds) != 0 {
		t.Fatalf("endpoints %+v outbounds %+v", options.Endpoints, options.Outbounds)
	}
	outer, inner := warpOf(t, options.Endpoints[0]), warpOf(t, options.Endpoints[1])
	if outer.Mode != "masque" || outer.Server != "1.1.1.1" || outer.ServerPort != 443 || outer.MASQUE.VHTTP != "h2" ||
		outer.MASQUE.ServerName != "www.cloudflare.com" || outer.Detour != "" {
		t.Fatalf("outer %+v %+v", outer, outer.MASQUE)
	}
	if inner.Mode != "wg" || inner.Server != "" || inner.Detour != options.Endpoints[0].Tag || inner.Scanner.Enabled {
		t.Fatalf("inner %+v", inner)
	}
	if !strings.HasPrefix(options.Endpoints[0].Tag, "Not YouTube") || outer.UniqueIdentifier == inner.UniqueIdentifier ||
		!strings.HasPrefix(outer.UniqueIdentifier, "aether-") {
		t.Fatalf("tags %q %q ids %q %q", options.Endpoints[0].Tag, options.Endpoints[1].Tag, outer.UniqueIdentifier, inner.UniqueIdentifier)
	}
}

func TestAetherSingleHops(t *testing.T) {
	options := parseAether(t, "aether://188.114.99.93:891?protocol=wg&scan=balanced&ip=v4#A10\n"+
		"aether://162.159.198.2:443?protocol=masque&scan=balanced&ip=v4&transport=h2&sni=consumer-masque.cloudflareclient.com&fragment=1#A11\n"+
		"aether://?scan=turbo&noize=off#scan")
	if len(options.Endpoints) != 3 {
		t.Fatalf("endpoints %+v", options.Endpoints)
	}
	wg, masque, scan := warpOf(t, options.Endpoints[0]), warpOf(t, options.Endpoints[1]), warpOf(t, options.Endpoints[2])
	if wg.Mode != "wg" || wg.Server != "188.114.99.93" || wg.ServerPort != 891 {
		t.Fatalf("wg %+v", wg)
	}
	if masque.Mode != "masque" || masque.ServerPort != 443 || masque.MASQUE.ServerName != "consumer-masque.cloudflareclient.com" || !masque.MASQUE.TLS.Fragment {
		t.Fatalf("masque %+v %+v", masque, masque.MASQUE)
	}
	if scan.Mode != "wg" || scan.Server != "" || !scan.Scanner.Enabled || scan.Scanner.SearchNoise || scan.Scanner.Count != 16 {
		t.Fatalf("scan %+v %+v", scan, scan.Scanner)
	}
}

func TestAetherTwoHops(t *testing.T) {
	options := parseAether(t, "aether://?protocol=gool&outer=188.114.97.1%3A4500&inner=162.159.195.117%3A864#gool\n"+
		"aether://?protocol=mim&transport=h2&outer=162.159.198.234%3A443&inner=162.159.198.18%3A443#mim")
	if len(options.Endpoints) != 4 {
		t.Fatalf("endpoints %+v", options.Endpoints)
	}
	gOuter, gInner := warpOf(t, options.Endpoints[0]), warpOf(t, options.Endpoints[1])
	if gOuter.Mode != "wg" || gOuter.Server != "188.114.97.1" || gInner.Mode != "wg" || gInner.Server != "162.159.195.117" ||
		gInner.ServerPort != 864 || gInner.Detour != options.Endpoints[0].Tag {
		t.Fatalf("gool %+v %+v", gOuter, gInner)
	}
	mOuter, mInner := warpOf(t, options.Endpoints[2]), warpOf(t, options.Endpoints[3])
	if mOuter.Mode != "masque" || mInner.Mode != "masque" || mInner.Server != "162.159.198.18" || mInner.Detour != options.Endpoints[2].Tag {
		t.Fatalf("mim %+v %+v", mOuter, mInner)
	}
}

func TestAetherCarriers(t *testing.T) {
	// psiphon inside WARP: psiphon dials through the warp endpoint
	options := parseAether(t, "aether://188.114.99.59:1180?protocol=wg&psiphon=chain&psiphon_mode=auto&region=FI#A13")
	if len(options.Outbounds) != 1 || len(options.Endpoints) != 1 || options.Outbounds[0].Type != C.TypePsiphon {
		t.Fatalf("%+v %+v", options.Outbounds, options.Endpoints)
	}
	psiphon := options.Outbounds[0].Options.(*T.PsiphonOutboundOptions)
	if psiphon.EgressRegion != "FI" || psiphon.Detour != options.Endpoints[0].Tag {
		t.Fatalf("psiphon %+v", psiphon)
	}

	// WARP through tor: MASQUE over HTTP/2, dialled through tor
	options = parseAether(t, "aether://162.159.198.248:443?protocol=masque&tor=reverse#A4")
	if len(options.Outbounds) != 1 || options.Outbounds[0].Type != C.TypeTor {
		t.Fatalf("%+v", options.Outbounds)
	}
	warp := warpOf(t, options.Endpoints[0])
	if warp.Detour != options.Outbounds[0].Tag || warp.MASQUE.VHTTP != "h2" {
		t.Fatalf("warp %+v", warp)
	}

	options = parseAether(t, "aether://?protocol=wg&tor=only&tor_bridges=auto#A8")
	if len(options.Outbounds) != 1 || len(options.Endpoints) != 0 || options.Outbounds[0].Type != C.TypeTor {
		t.Fatalf("%+v %+v", options.Outbounds, options.Endpoints)
	}
}

func TestAetherRefused(t *testing.T) {
	for _, link := range []string{
		"aether://?protocol=wg&tor=reverse#wg-through-tor",
		"aether://?protocol=nope#unknown",
		"aether://?protocol=masque&tor=chain&psiphon=chain#both-inside",
	} {
		if _, err := ray2sing.Ray2SingboxOptions(context.Background(), link, false); err == nil {
			t.Errorf("%s: no error", link)
		}
	}
}
