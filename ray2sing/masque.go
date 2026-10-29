package ray2sing

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

// A masque:// link is a WARP device already enrolled for MASQUE:
//
//		masque://<device id>?key=<ECDSA key>&peer=<endpoint key>&addr=172.16.0.2&endpoint=162.159.198.60:443&endpoint6=[2606:4700:103::2]:443&transport=h2&sni=www.cloudflare.com#name
//
//	  - key, peer: the device's private key and the endpoint's public key (base64 DER).
//	  - addr, addr6: the tunnel addresses. endpoint, endpoint6: the HTTP/3 endpoints; cfdef: the
//	    HTTP/2 endpoint (Cloudflare's when missing).
//	  - transport (or vhttp): h3, h2 or auto. sni: the TLS server name. split: split the
//	    ClientHello (HTTP/2).
//	  - inner: a masque:// link run through this one (MASQUE in MASQUE).
//	  - the MASQUE and scanner parameters of warp:// (see warp.go), and mtu, ipv6, license.
//
// Other parameters of the apps that write these links (framing, junk, v2bait, cfwarp, cfscan,
// cfobfs, cfkey) have no counterpart and are ignored.
func MasqueSingbox(link string) (*T.Outbound, error) {
	u, err := ParseUrl(link, 0)
	if err != nil {
		return nil, err
	}
	param := func(keys ...string) string { return getOneOfN(u.Params, "", keys...) }
	id := u.Username
	if id == "" {
		id = u.Hostname
	}
	device := &T.MASQUEDeviceOptions{
		ID:                id,
		PrivateKey:        param("key", "private_key"),
		EndpointPublicKey: param("peer", "endpoint_public_key"),
		IPv4:              param("addr", "ipv4"),
		IPv6:              param("addr6", "ipv6_addr"),
		EndpointH2V4:      param("cfdef", "endpoint_h2"),
		License:           param("license"),
	}
	for _, endpoint := range []string{param("endpoint"), param("endpoint6")} {
		if endpoint == "" {
			continue
		}
		if isIPv6Endpoint(endpoint) {
			device.EndpointV6 = endpoint
		} else {
			device.EndpointV4 = endpoint
		}
	}
	if device.EndpointH2V4 != "" && isIPv6Endpoint(device.EndpointH2V4) {
		device.EndpointH2V6, device.EndpointH2V4 = device.EndpointH2V4, ""
	}

	options := &T.MASQUEOutboundOptions{
		Device: device,
		MASQUEOutboundTLSOptions: T.MASQUEOutboundTLSOptions{
			Insecure:              toBool(param("insecure", "masque_insecure"), false),
			CipherSuites:          splitList(param("cipher_suites")),
			Fragment:              param("split") != "" || toBool(param("fragment"), false),
			FragmentFallbackDelay: warpDuration(param("fragment_fallback_delay")),
			RecordFragment:        toBool(param("record_fragment"), false),
			KernelTx:              toBool(param("kernel_tx"), false),
			KernelRx:              toBool(param("kernel_rx"), false),
		},
		UseIPv6:              toBool(param("ipv6", "use_ipv6", "masque_ipv6"), false),
		UDPTimeout:           warpDuration(param("udp_timeout")),
		UDPKeepalivePeriod:   warpDuration(param("udp_keepalive_period")),
		UDPInitialPacketSize: uint16(toInt(param("udp_initial_packet_size"))),
		MTU:                  uint32(toInt(param("mtu"))),
		UniqueIdentifier:     id,
		ReconnectDelay:       warpDuration(param("reconnect_delay")),
		VHTTP:                strings.ToLower(param("vhttp", "transport")),
		ServerName:           param("sni", "masque_sni", "server_name"),
		Scanner: &T.WARPScannerOptions{
			Enabled:     toBool(param("scanner", "scan"), true),
			Count:       toInt(param("scan_count")),
			Concurrency: toInt(param("scan_concurrency")),
			MaxRTT:      warpDuration(param("max_rtt", "scan_max_rtt")),
			Timeout:     warpDuration(param("scan_timeout")),
		},
	}
	if curves := param("curve_preferences"); curves != "" {
		_ = json.Unmarshal(jsonStringList(curves), &options.MASQUEOutboundTLSOptions.CurvePreferences)
	}
	switch options.VHTTP {
	case "h2", "h3", "auto":
	default:
		options.VHTTP = ""
	}
	out := &T.Outbound{
		Type:    C.TypeMASQUE,
		Tag:     u.Name,
		Options: options,
	}
	if out.Tag == "" {
		out.Tag = "MASQUE"
	}
	return out, nil
}

func isIPv6Endpoint(endpoint string) bool {
	if strings.HasPrefix(endpoint, "[") {
		return true
	}
	addr, err := netip.ParseAddr(endpoint)
	return err == nil && addr.Is6()
}

// expandInnerLinks writes a masque:// link with an inner link as the chain "inner -> outer":
// the inner tunnel runs through the outer one.
func expandInnerLinks(config string) string {
	if !strings.HasPrefix(config, "masque://") || strings.Contains(config, " -> ") {
		return config
	}
	u, err := url.Parse(config)
	if err != nil {
		return config
	}
	query := u.Query()
	inner := query.Get("inner")
	if inner == "" {
		return config
	}
	query.Del("inner")
	u.RawQuery = query.Encode()
	return expandInnerLinks(inner) + " -> " + u.String()
}
