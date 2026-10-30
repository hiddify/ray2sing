package ray2sing

import (
	"encoding/json"
	"net/netip"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/wireguard-go/hiddify"
)

// AmneziaWG values that change only what the client sends before a handshake (junk packets,
// i1–i5, the QUIC masquerade ip/id) work with a plain WireGuard server when s1–s4 are 0 and h1–h4
// are WireGuard's own message types 1–4: WARP configs with AmneziaWG noise are written so. The awg
// endpoint has no recovery of a stuck socket, which the WireGuard endpoint has, so such a config
// whose peer has reserved bytes (WARP) becomes a WireGuard endpoint that sends the same packets as
// noise. Any other config becomes an awg endpoint, which keeps the reserved bytes when its messages
// have room for them (see option.AwgOptions.ReservedMessageTypes) and drops them otherwise.

// awgAsWireGuardNoise is the WireGuard noise that sends what awg sends before a handshake: i1–i5
// (or the QUIC masquerade), then jc junk packets of jmin–jmax random bytes. ok is false when awg
// changes the WireGuard packets themselves, or uses a tag that noise cannot build.
func awgAsWireGuardNoise(awg T.AwgOptions) (noise hiddify.NoiseOptions, ok bool) {
	if awg.S1 != 0 || awg.S2 != 0 || awg.S3 != 0 || awg.S4 != 0 || awg.HeaderProtectionKey != "" ||
		awg.ContentPaddingAddition != "" || awg.RekeyAfterTime != "" || awg.RekeyTimeout != "" ||
		awg.RejectAfterTime != "" || awg.KeepaliveTimeout != "" || awg.MaxHandshakeAttempts != "" ||
		awg.RandomTrailers || awg.DisableCookies {
		return noise, false
	}
	for i, h := range []string{awg.H1, awg.H2, awg.H3, awg.H4} {
		if h != "" && h != strconv.Itoa(i+1) {
			return noise, false
		}
	}
	packets := []string{awg.I1, awg.I2, awg.I3, awg.I4, awg.I5}
	if awg.IP != "" || awg.ID != "" {
		if awg.IP != "quic" || awg.ID == "" || awg.I1 != "" {
			return noise, false
		}
		packets[0] = "<qi " + awg.ID + ">"
	}
	fake := hiddify.FakePacketOptions{Mode: hiddify.NoiseModeRaw}
	for _, packet := range packets {
		if packet == "" {
			continue
		}
		if _, err := hiddify.ExpandPacket(packet); err != nil {
			return noise, false
		}
		fake.Packets = append(fake.Packets, packet)
	}
	if awg.Jc > 0 && awg.Jmax > 0 {
		fake.Count = hiddify.Range{From: int32(awg.Jc), To: int32(awg.Jc)}
		fake.Size = hiddify.Range{From: int32(awg.Jmin), To: int32(awg.Jmax)}
	}
	fake.Enabled = len(fake.Packets) > 0 || fake.Count.To > 0
	return hiddify.NoiseOptions{FakePacket: fake}, true
}

func hasReserved(peers []T.WireGuardPeer) bool {
	for _, peer := range peers {
		if len(peer.Reserved) > 0 {
			return true
		}
	}
	return false
}

// amneziaWireGuardEndpoint is the endpoint for WireGuard options with AmneziaWG values (see above).
func amneziaWireGuardEndpoint(tag string, wg T.WireGuardEndpointOptions, awg T.AwgOptions) *T.Endpoint {
	if !awg.IsAvailble() {
		return &T.Endpoint{Type: C.TypeWireGuard, Tag: tag, Options: &wg}
	}
	if noise, ok := awgAsWireGuardNoise(awg); ok && hasReserved(wg.Peers) {
		wg.Noise = noise
		return &T.Endpoint{Type: C.TypeWireGuard, Tag: tag, Options: &wg}
	}
	opts := T.AwgEndpointOptions{
		PrivateKey:    wg.PrivateKey,
		Address:       wg.Address,
		MTU:           wg.MTU,
		ListenPort:    wg.ListenPort,
		Awg:           awg,
		DialerOptions: wg.DialerOptions,
	}
	_, reservedErr := awg.ReservedMessageTypes()
	for _, peer := range wg.Peers {
		var reserved []uint8
		if reservedErr == nil && len(wg.Peers) == 1 {
			reserved = peer.Reserved
		}
		opts.Peers = append(opts.Peers, T.AwgPeerOptions{
			Reserved:                    reserved,
			Address:                     peer.Address,
			Port:                        peer.Port,
			PublicKey:                   peer.PublicKey,
			PresharedKey:                peer.PreSharedKey,
			AllowedIPs:                  badoption.Listable[netip.Prefix](peer.AllowedIPs),
			PersistentKeepaliveInterval: peer.PersistentKeepaliveInterval,
		})
	}
	return &T.Endpoint{Type: C.TypeAwg, Tag: tag, Options: &opts}
}

// awgFields are the AmneziaWG values that sing-box-lx writes in a WireGuard endpoint, next to its
// own fields, and Clash in "amnezia-wg-option".
var awgFields = []string{
	"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
	"ip", "id", "ib",
}

// wireGuardOnlyFields have no awg endpoint equivalent.
var wireGuardOnlyFields = []string{"system", "name", "workers", "udp_timeout", "noise"}

// MoveAmneziaWireGuardFields converts the WireGuard endpoints of a sing-box JSON config that carry
// AmneziaWG values in sing-box-lx's form ("jc", "i1", "ip": "quic", ... next to "private_key"),
// which sing-box does not read: into a WireGuard endpoint with noise or an awg endpoint (see above).
// A peer without allowed_ips gets all addresses, as Clash's WireGuard proxies mean.
func MoveAmneziaWireGuardFields(endpoints []any) []any {
	for _, item := range endpoints {
		endpoint, isObject := item.(map[string]any)
		if !isObject || endpoint["type"] != C.TypeWireGuard {
			continue
		}
		peers, _ := endpoint["peers"].([]any)
		reserved := false
		for _, item := range peers {
			if peer, isObject := item.(map[string]any); isObject {
				if _, exists := peer["allowed_ips"]; !exists {
					peer["allowed_ips"] = []any{"0.0.0.0/0", "::/0"}
				}
				if list, isList := peer["reserved"].([]any); isList && len(list) > 0 {
					reserved = true
				} else if text, isText := peer["reserved"].(string); isText && text != "" {
					reserved = true
				}
			}
		}
		values := map[string]any{}
		for _, key := range awgFields {
			if value, exists := endpoint[key]; exists {
				values[key] = awgValue(key, value)
				delete(endpoint, key)
			}
		}
		if len(values) == 0 {
			continue
		}
		var awg T.AwgOptions
		if content, err := json.Marshal(values); err != nil || json.Unmarshal(content, &awg) != nil {
			continue
		}
		if noise, ok := awgAsWireGuardNoise(awg); ok && reserved {
			content, _ := json.Marshal(&noise)
			var noiseValue any
			json.Unmarshal(content, &noiseValue)
			endpoint["noise"] = noiseValue
			continue
		}
		endpoint["type"] = C.TypeAwg
		endpoint["awg"] = values
		for _, key := range wireGuardOnlyFields {
			delete(endpoint, key)
		}
		_, reservedErr := awg.ReservedMessageTypes()
		for _, item := range peers {
			if peer, isObject := item.(map[string]any); isObject {
				if reservedErr != nil || len(peers) > 1 {
					delete(peer, "reserved")
				}
				delete(peer, "name")
				if psk, exists := peer["pre_shared_key"]; exists {
					peer["preshared_key"] = psk
					delete(peer, "pre_shared_key")
				}
			}
		}
	}
	return endpoints
}

// awgValue is value as the awg options read it: h1–h4 are strings, the rest of the numbers are
// numbers (Clash and sing-box-lx write either).
func awgValue(key string, value any) any {
	switch key {
	case "h1", "h2", "h3", "h4":
		switch number := value.(type) {
		case float64:
			return strconv.FormatInt(int64(number), 10)
		case int:
			return strconv.Itoa(number)
		}
	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4":
		if text, isText := value.(string); isText {
			if number, err := strconv.Atoi(text); err == nil {
				return number
			}
		}
	}
	return value
}
