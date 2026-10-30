package ray2sing

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// A warp:// link sets every option of the warp endpoint:
//
//	warp://<unique id>@<server|auto>:<port>?mode=auto&ifpm=dns-google&scanner=1#name
//
//   - mode: wg (or wireguard), awg, masque or auto; auto, the fastest tunnel that answers, when
//     it is missing or unknown.
//   - noise of WireGuard: ifp (count), ifps (size), ifpd (delay), ifpm (mode: quic, raw, or a
//     preset of warpscan.NoisePresets such as dns-google, quic, sip; dns and random name
//     dns-google and xray-random), ifpsni (SNI of QUIC noise), ifpp (packet templates, comma
//     separated), ifph (hex header), ifpnomodify; Xray's wnoise, wnoisecount, wpayloadsize and
//     wnoisedelay too. A preset is also the junk of AmneziaWG when the link has no AmneziaWG
//     fields.
//   - AmneziaWG: jc, jmin, jmax, s1-s4, h1-h4, i1-i5, and header_protection_key,
//     content_padding_addition, rekey_after_time, rekey_timeout, reject_after_time,
//     keepalive_timeout, max_handshake_attempts, random_trailers, disable_cookies, ip, id, ib.
//   - MASQUE: vhttp (h3, h2, auto), masque_sni, masque_insecure, masque_ipv6,
//     udp_keepalive_period, udp_initial_packet_size, reconnect_delay, fragment,
//     fragment_fallback_delay, record_fragment, cipher_suites, curve_preferences, kernel_tx,
//     kernel_rx.
//   - scanner: scanner and search_noise (both on unless set to 0 or false, and off behind a
//     detour), scan_ports, scan_cidrs, max_rtt, scan_timeout, scan_count, scan_concurrency,
//     noise_presets.
//   - mtu (1280), workers, udp_timeout, license, recreate.
//
// A server of auto, default, random, auto4 or auto6 leaves the choice to the endpoint. Durations
// are Go durations, or seconds.

var warpModes = map[string]string{"wg": "wg", "wireguard": "wg", "awg": "awg", "masque": "masque", "auto": "auto"}

var warpNoisePresetAliases = map[string]string{"dns": "dns-google", "random": "xray-random"}

func WarpSingbox(url string) (*T.Endpoint, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	param := func(keys ...string) string { return getOneOfN(u.Params, "", keys...) }
	has := func(keys ...string) bool {
		for _, key := range keys {
			if _, ok := u.Params[normalizeStr(key)]; ok {
				return true
			}
		}
		return false
	}
	getInt := func(key string) int { return toInt(param(key)) }

	mode, ok := warpModes[strings.ToLower(param("mode"))]
	if !ok {
		mode = "auto"
	}
	server := u.Hostname
	switch strings.ToLower(server) {
	case "auto", "auto4", "auto6", "default", "random":
		server = ""
	}

	noise := getWireGuardNoise(u.Params, false)
	preset, isPreset := warpNoisePreset(param("ifpm"))
	if isPreset {
		explicit := noise.FakePacket
		noise = preset.WireGuard()
		if explicit.Count.To != 0 {
			noise.FakePacket.Count = explicit.Count
		}
		if explicit.Size.To != 0 {
			noise.FakePacket.Size = explicit.Size
		}
		if explicit.Delay.To != 0 {
			noise.FakePacket.Delay = explicit.Delay
		}
	}
	if has("ifpsni", "ifpp", "ifph", "ifpnomodify") {
		noise.FakePacket.Enabled = true
		noise.FakePacket.SNI = param("ifpsni")
		if packets := param("ifpp"); packets != "" {
			noise.FakePacket.Packets = append(noise.FakePacket.Packets, strings.Split(packets, ",")...)
		}
		if header := param("ifph"); header != "" {
			noise.FakePacket.Header, _ = hex.DecodeString(strings.TrimPrefix(strings.ToLower(header), "0x"))
		}
		noise.FakePacket.NoModify = toBool(param("ifpnomodify"), false)
	}

	awg := &T.AwgOptions{
		Jc: getInt("jc"), Jmin: getInt("jmin"), Jmax: getInt("jmax"),
		S1: getInt("s1"), S2: getInt("s2"), S3: getInt("s3"), S4: getInt("s4"),
		H1: param("h1"), H2: param("h2"), H3: param("h3"), H4: param("h4"),
		I1: param("i1"), I2: param("i2"), I3: param("i3"), I4: param("i4"), I5: param("i5"),

		HeaderProtectionKey:    param("header_protection_key"),
		ContentPaddingAddition: T.AwgRange(param("content_padding_addition")),
		RekeyAfterTime:         T.AwgRange(param("rekey_after_time")),
		RekeyTimeout:           T.AwgRange(param("rekey_timeout")),
		RejectAfterTime:        T.AwgRange(param("reject_after_time")),
		KeepaliveTimeout:       T.AwgRange(param("keepalive_timeout")),
		MaxHandshakeAttempts:   T.AwgRange(param("max_handshake_attempts")),
		RandomTrailers:         toBool(param("random_trailers"), false),
		DisableCookies:         toBool(param("disable_cookies"), false),
		IP:                     param("ip"),
		ID:                     param("id"),
		IB:                     param("ib"),
	}
	if !awg.IsAvailble() {
		awg = nil
		if isPreset {
			awg = preset.AWG(nil)
		}
	}

	var masque *T.WARPMASQUEOptions
	if has("vhttp", "masque_sni", "masque_insecure", "masque_ipv6", "udp_keepalive_period", "udp_initial_packet_size", "reconnect_delay",
		"fragment", "fragment_fallback_delay", "record_fragment", "cipher_suites", "curve_preferences", "kernel_tx", "kernel_rx") {
		masque = &T.WARPMASQUEOptions{
			Enabled: true,
			TLS: T.MASQUEOutboundTLSOptions{
				Insecure:              toBool(param("masque_insecure"), false),
				CipherSuites:          splitList(param("cipher_suites")),
				Fragment:              toBool(param("fragment"), false),
				FragmentFallbackDelay: warpDuration(param("fragment_fallback_delay")),
				RecordFragment:        toBool(param("record_fragment"), false),
				KernelTx:              toBool(param("kernel_tx"), false),
				KernelRx:              toBool(param("kernel_rx"), false),
			},
			UseIPv6:              toBool(param("masque_ipv6"), false),
			UDPKeepalivePeriod:   warpDuration(param("udp_keepalive_period")),
			UDPInitialPacketSize: uint16(getInt("udp_initial_packet_size")),
			ReconnectDelay:       warpDuration(param("reconnect_delay")),
			VHTTP:                param("vhttp"),
			ServerName:           param("masque_sni"),
		}
		if curves := param("curve_preferences"); curves != "" {
			_ = json.Unmarshal(jsonStringList(curves), &masque.TLS.CurvePreferences)
		}
	}

	scanner := &T.WARPScannerOptions{
		Enabled:     toBool(param("scanner", "scan"), true),
		SearchNoise: toBool(param("search_noise", "noise_scan"), true),
		Count:       getInt("scan_count"),
		Concurrency: getInt("scan_concurrency"),
		MaxRTT:      warpDuration(param("max_rtt", "scan_max_rtt")),
		Timeout:     warpDuration(param("scan_timeout")),
	}
	for _, port := range splitList(param("scan_ports")) {
		if value := toInt(port); value > 0 && value < 65536 {
			scanner.Ports = append(scanner.Ports, uint16(value))
		}
	}
	if cidrs := param("scan_cidrs"); cidrs != "" {
		_ = json.Unmarshal(jsonStringList(cidrs), &scanner.CIDRs)
	}
	for _, name := range splitList(param("noise_presets")) {
		if preset, ok := warpNoisePreset(name); ok {
			scanner.NoisePresets = append(scanner.NoisePresets, preset.Name)
		}
	}

	options := &T.WARPEndpointOptions{
		ServerOptions: T.ServerOptions{
			Server:     server,
			ServerPort: u.Port,
		},
		UniqueIdentifier: u.Username,
		Noise:            noise,
		MTU:              uint32(toInt(getOneOfN(u.Params, "1280", "mtu"))),
		Mode:             mode,
		AWG:              awg,
		MASQUE:           masque,
		Scanner:          scanner,
		Workers:          getInt("workers"),
		UDPTimeout:       warpDuration(param("udp_timeout")),
		Profile: T.WARPProfile{
			License:  param("license"),
			Recreate: toBool(param("recreate"), false),
		},
	}
	out := T.Endpoint{
		Type:    C.TypeWARP,
		Tag:     u.Name,
		Options: options,
	}

	if out.Tag == "" {
		out.Tag = "WARP"
	}
	return &out, nil
}

// warpBehindDetour sets up a warp endpoint behind a detour (the outer WARP of WARP in WARP). The
// scanner is off: its probes would go through the detour, which does not reach Cloudflare's
// endpoints the way WARP does. The ports are not rotated either: through a detour, a port that
// gets no handshake says more about the detour than about the port.
func warpBehindDetour(endpoint *T.Endpoint) {
	options, ok := endpoint.Options.(*T.WARPEndpointOptions)
	if !ok || endpoint.Type != C.TypeWARP {
		return
	}
	if options.Scanner != nil {
		options.Scanner.Enabled = false
		options.Scanner.SearchNoise = false
	}
	rotatePorts := false
	options.RotatePorts = &rotatePorts
}

// disableMasqueScanner turns off the scanner of a MASQUE outbound behind a detour, as
// warpBehindDetour does.
func disableMasqueScanner(outbound *T.Outbound) {
	if options, ok := outbound.Options.(*T.MASQUEOutboundOptions); ok && options.Scanner != nil {
		options.Scanner.Enabled = false
	}
}

func warpNoisePreset(name string) (warpscan.NoisePreset, bool) {
	name = strings.ToLower(name)
	if alias, ok := warpNoisePresetAliases[name]; ok {
		name = alias
	}
	return warpscan.NoisePresetByName(name)
}

func warpDuration(value string) badoption.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		return badoption.Duration(time.Duration(seconds * float64(time.Second)))
	}
	duration, _ := time.ParseDuration(value)
	return badoption.Duration(duration)
}

func splitList(value string) []string {
	var list []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list
}

func jsonStringList(value string) []byte {
	content, _ := json.Marshal(splitList(value))
	return content
}
