package ray2sing

import (
	"context"
	"testing"

	T "github.com/sagernet/sing-box/option"
)

// wnoise names a noise preset (sip, dns, stun, ...) next to Xray's quic and random.
func TestH_WireGuardLinkNoisePreset(t *testing.T) {
	link := "wireguard://oHq9m3BPpZ5i%2Ba9xRkp%2FqFBD7lSp04hWYfqK8WgExUs%3D@8.6.112.248:2408?wnoise=sip&wnoisecount=3" +
		"&address=172.16.0.2%2F32&reserved=52%2C78%2C139&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D#sip"
	options, err := Ray2SingboxOptions(context.Background(), link, false)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := options.Endpoints[0].Options.(*T.WireGuardEndpointOptions)
	fake := endpoint.Noise.FakePacket
	if !fake.Enabled || fake.Mode != "sip" || fake.Count.To != 3 {
		t.Fatalf("noise: %+v", fake)
	}
}

// An AmneziaWG ip naming a preset: with WARP's reserved bytes it becomes WireGuard noise of that
// preset with its jc; without, an awg endpoint that keeps ip.
func TestH_AmneziaIPNamesNoisePreset(t *testing.T) {
	endpoint := func(reserved bool) map[string]any {
		peer := map[string]any{"address": "8.6.112.248", "port": 2408, "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="}
		if reserved {
			peer["reserved"] = []any{52, 78, 139}
		}
		return MoveAmneziaWireGuardFields([]any{map[string]any{
			"type": "wireguard", "tag": "w", "private_key": "oHq9m3BPpZ5i+a9xRkp/qFBD7lSp04hWYfqK8WgExUs=",
			"address": []any{"172.16.0.2/32"}, "jc": 4, "jmin": 40, "jmax": 70, "ip": "dns", "peers": []any{peer},
		}})[0].(map[string]any)
	}
	warp := endpoint(true)
	noise, _ := warp["noise"].(map[string]any)
	fake, _ := noise["fake_packet"].(map[string]any)
	if warp["type"] != "wireguard" || fake == nil || fake["mode"] != "dns" || fake["enabled"] != true || fake["count"] != "4-4" {
		t.Fatalf("WARP endpoint: %#v", warp)
	}
	awg := endpoint(false)
	if fields, _ := awg["awg"].(map[string]any); awg["type"] != "awg" || fields["ip"] != "dns" {
		t.Fatalf("awg endpoint: %#v", awg)
	}
}
