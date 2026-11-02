package ray2sing

import (
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"strconv"
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
//
// A link from MahsaNG (its MasqueFmt, also read by xray-knife) has the device's key before the
// "@" and the endpoint, with its port, after it; there is no key parameter:
//
//		masque://<private key, base64>@162.159.198.2:8095?transport=h3&address=172.16.0.2/32&mtu=1280&sni=consumer-masque.cloudflareclient.com&insecure=1&keepalive=5#name
//
//	  - the key: PKCS #8 or SEC 1 DER in base64, URL-encoded or not. The endpoint's key is not in
//	    the link: Cloudflare's MASQUE edge has one fixed certificate, which sing-box knows. A
//	    device Cloudflare refuses is replaced by one sing-box registers, as for a profile.
//	  - address: the tunnel addresses, CIDRs separated by commas; 172.16.0.2/32 when missing.
//	  - transport: h3 or h2; missing, HTTP/3 falling back to HTTP/2. mtu. keepalive: seconds
//	    between keepalives. sni.
//	  - insecure: on unless 0, as in MahsaNG. pin (or pinnedPeerPublicKeySha256): SHA-256 of the
//	    endpoint's key, verified instead of the edge's key. ech (or echConfigList): an ECH config.
//	  - packets, with length and interval: Xray's fragment; the ClientHello is split (HTTP/2).
//	  - the scanner parameters of warp://.
//	  - remoteDNS, domainStrategy, fm and wnoise, wnoisecount, wnoisedelay, wpayloadsize have no
//	    counterpart (DNS is sing-box's, the tunnel sends no QUIC noise) and are ignored.
//	  - "+" in the name is a space, as Java's URLEncoder writes it.
//
// Other apps write the endpoint as the link's host, with the device's key as a parameter:
//
//		masque://162.159.198.2:443?privateKey=<private key, base64>&ip=172.16.0.2/32&mtu=1280&keepalive=5&sni=consumer-masque.cloudflareclient.com#name
//
//	  - a host that is an IP address or a domain is the endpoint, never a device id (a device id
//	    has no dot); with no endpoint parameter, it is the endpoint.
//	  - privateKey (or key, private_key): the device's key, as after the "@" above.
//	  - ip (or address): the tunnel addresses, as address above.
//	  - udp and flag have no counterpart and are ignored.
func MasqueSingbox(link string) (*T.Outbound, error) {
	key, link, isKeyLink := splitMasqueKeyLink(link)
	u, err := ParseUrl(link, 443)
	if err != nil {
		return nil, err
	}
	param := func(keys ...string) string { return getOneOfN(u.Params, "", keys...) }
	// the host is the endpoint when it is an address and no endpoint parameter names one
	hostIsEndpoint := !isKeyLink && u.Username == "" && param("endpoint", "endpoint6") == "" && isMasqueAddress(u.Hostname)
	id := u.Username
	if id == "" && !isKeyLink && !hostIsEndpoint {
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
	insecure := toBool(param("insecure", "masque_insecure"), false)
	if isKeyLink || hostIsEndpoint {
		if isKeyLink {
			device.PrivateKey = key
		}
		endpoint := net.JoinHostPort(u.Hostname, strconv.Itoa(int(u.Port)))
		if isIPv6Endpoint(u.Hostname) {
			device.EndpointV6 = endpoint
		} else {
			device.EndpointV4 = endpoint
		}
		for _, address := range splitList(param("address", "ip")) {
			if prefix, err := netip.ParsePrefix(address); err == nil {
				address = prefix.Addr().String()
			}
			addr, err := netip.ParseAddr(address)
			switch {
			case err != nil:
			case addr.Is4() && device.IPv4 == "":
				device.IPv4 = addr.String()
			case addr.Is6() && device.IPv6 == "":
				device.IPv6 = addr.String()
			}
		}
		if device.IPv4 == "" && device.IPv6 == "" {
			device.IPv4 = "172.16.0.2"
		}
		if isKeyLink {
			insecure = toBool(param("insecure", "allow_insecure"), true)
		}
		u.Name = strings.ReplaceAll(u.Name, "+", " ")
	}

	options := &T.MASQUEOutboundOptions{
		Device: device,
		MASQUEOutboundTLSOptions: T.MASQUEOutboundTLSOptions{
			Insecure:              insecure,
			CipherSuites:          splitList(param("cipher_suites")),
			Fragment:              param("split") != "" || toBool(param("fragment"), false),
			FragmentFallbackDelay: warpDuration(param("fragment_fallback_delay")),
			RecordFragment:        toBool(param("record_fragment"), false),
			KernelTx:              toBool(param("kernel_tx"), false),
			KernelRx:              toBool(param("kernel_rx"), false),
		},
		UseIPv6:              toBool(param("ipv6", "use_ipv6", "masque_ipv6"), false),
		UDPTimeout:           warpDuration(param("udp_timeout")),
		UDPKeepalivePeriod:   warpDuration(param("udp_keepalive_period", "keepalive", "keep_alive_period")),
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
	if pins := splitList(param("pin", "pinned_peer_public_key_sha256", "certificate_public_key_sha256")); len(pins) > 0 {
		options.MASQUEOutboundTLSOptions.CertificatePublicKeySHA256 = pins
	}
	if ech := strings.ReplaceAll(param("ech", "ech_config_list"), " ", "+"); ech != "" { // a "+" of base64 read as a space
		options.MASQUEOutboundTLSOptions.ECH = &T.OutboundECHOptions{Enabled: true, Config: []string{ech}}
	}
	if param("packets") != "" { // Xray's fragment
		options.MASQUEOutboundTLSOptions.Fragment = true
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

// splitMasqueKeyLink reads a link with the device's key before the "@" (MahsaNG's shape): the
// key, URL-decoded, and the link without it, for ParseUrl. The key is split off by hand: a "/"
// left raw in its base64 would end the authority for url.Parse. A link with a key parameter, or
// nothing before the "@", is not of this shape and comes back as it is.
func splitMasqueKeyLink(link string) (key string, rest string, ok bool) {
	const scheme = "masque://"
	if !strings.HasPrefix(link, scheme) {
		return "", link, false
	}
	base, fragment, hasFragment := strings.Cut(link, "#")
	body, rawQuery, hasQuery := strings.Cut(strings.TrimPrefix(base, scheme), "?")
	at := strings.LastIndex(body, "@")
	if at <= 0 {
		return "", link, false
	}
	if query, err := url.ParseQuery(rawQuery); err == nil && (query.Get("key") != "" || query.Get("private_key") != "") {
		return "", link, false
	}
	key, err := url.PathUnescape(body[:at]) // "+" stays a "+": base64 has no spaces
	if err != nil {
		key = body[:at]
	}
	rest = scheme + body[at+1:]
	if hasQuery {
		rest += "?" + rawQuery
	}
	if hasFragment {
		rest += "#" + fragment
	}
	return strings.TrimSpace(key), rest, true
}

// isMasqueAddress reports whether a link's host is an endpoint address: an IP address or a
// domain. A device id is a bare identifier, without a dot.
func isMasqueAddress(host string) bool {
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return true
	}
	return strings.Contains(host, ".")
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
