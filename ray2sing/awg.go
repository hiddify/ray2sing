package ray2sing

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func AWGSingboxTxt(content string) (*T.Endpoint, error) {

	var (
		privateKey                         string
		mtu                                uint32
		addresses                          []netip.Prefix
		jc, jmin, jmax                     int
		s1, s2, s3, s4                     int
		h1, h2, h3, h4, i1, i2, i3, i4, i5 string

		peer     T.AwgPeerOptions
		reserved []uint8
	)

	section := ""
	name := ""

	lines := strings.Split(content, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		// key = value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch section {
		case "interface":
			switch key {
			case "Name": // the "# Name" comment, see confNamePattern
				name = val
			case "PrivateKey":
				privateKey = val
			case "MTU":
				v, _ := strconv.Atoi(val)
				mtu = uint32(v)

			case "Address":
				for _, add := range strings.Split(val, ",") {
					pfx, err := netip.ParsePrefix(strings.TrimSpace(add))
					if err != nil {
						return nil, fmt.Errorf("invalid Address: %w", err)
					}
					addresses = append(addresses, pfx)
				}
			case "Jc":
				jc, _ = strconv.Atoi(val)
			case "Jmin":
				jmin, _ = strconv.Atoi(val)
			case "Jmax":
				jmax, _ = strconv.Atoi(val)

			case "S1":
				s1, _ = strconv.Atoi(val)
			case "S2":
				s2, _ = strconv.Atoi(val)
			case "S3":
				s3, _ = strconv.Atoi(val)
			case "S4":
				s4, _ = strconv.Atoi(val)
			case "H1":
				h1 = val
			case "H2":
				h2 = val
			case "H3":
				h3 = val
			case "H4":
				h4 = val
			case "I1":
				i1 = val
			case "I2":
				i2 = val
			case "I3":
				i3 = val
			case "I4":
				i4 = val
			case "I5":
				i5 = val
			}

		case "peer":
			switch key {
			case "PublicKey":
				peer.PublicKey = val
			case "PresharedKey":
				peer.PresharedKey = val

			case "AllowedIPs":
				for _, ip := range strings.Split(val, ",") {
					pfx, err := netip.ParsePrefix(strings.TrimSpace(ip))
					if err != nil {
						return nil, fmt.Errorf("invalid AllowedIPs: %w", err)
					}
					peer.AllowedIPs = append(peer.AllowedIPs, pfx)
				}

			case "Endpoint":
				host, portStr, err := net.SplitHostPort(val)
				if err != nil {
					return nil, fmt.Errorf("invalid Endpoint: %w", err)
				}
				port, err := strconv.Atoi(portStr)
				if err != nil {
					return nil, fmt.Errorf("invalid Endpoint port: %w", err)
				}
				peer.Address = host
				peer.Port = uint16(port)

			case "PersistentKeepalive":
				v, _ := strconv.Atoi(val)
				peer.PersistentKeepaliveInterval = uint16(v)
			case "Reserved": // WARP generators write the client id so
				for _, part := range strings.Split(val, ",") {
					if num, err := strconv.ParseUint(strings.TrimSpace(part), 10, 8); err == nil {
						reserved = append(reserved, uint8(num))
					}
				}
			}
		}
	}

	if privateKey == "" {
		return nil, errors.New("missing PrivateKey")
	}

	if peer.Address == "" || peer.Port == 0 {
		return nil, errors.New("missing peer Endpoint")
	}
	if len(peer.AllowedIPs) == 0 {
		peer.AllowedIPs = badoption.Listable[netip.Prefix]([]netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
		})
	}
	awg := T.AwgOptions{
		Jc:   jc,
		Jmin: jmin,
		Jmax: jmax,

		S1: s1,
		S2: s2,
		S3: s3,
		S4: s4,
		H1: h1,
		H2: h2,
		H3: h3,
		H4: h4,

		I1: i1,
		I2: i2,
		I3: i3,
		I4: i4,
		I5: i5,
	}
	wg := T.WireGuardEndpointOptions{
		PrivateKey: privateKey,
		Address:    badoption.Listable[netip.Prefix](addresses),
		MTU:        mtu,
		Peers: []T.WireGuardPeer{
			T.WireGuardPeer{
				Address:                     peer.Address,
				Port:                        peer.Port,
				PreSharedKey:                peer.PresharedKey,
				PublicKey:                   peer.PublicKey,
				AllowedIPs:                  T.LegacyListable[netip.Prefix](peer.AllowedIPs),
				PersistentKeepaliveInterval: peer.PersistentKeepaliveInterval,
				Reserved:                    reserved,
			},
		},
	}
	if !awg.IsAvailble() {
		if name == "" {
			name = "wireguard"
		}
		wg.Noise = defaultWireguardNoiseOptions()
		return amneziaWireGuardEndpoint(name, wg, awg), nil
	}
	if name == "" {
		name = "awg"
	}
	return amneziaWireGuardEndpoint(name, wg, awg), nil
}

func AWGSingbox(raw string) (*T.Endpoint, error) {
	content := raw
	splt := strings.SplitN(raw, "://", 2)
	if len(splt) == 2 {
		d, _ := decodeBase64IfNeeded(splt[1])
		raw = splt[0] + "://" + d
		content = d
	}
	u, err := ParseUrl(raw, 0)

	if err != nil || len(u.Params) == 0 {
		if end, err2 := AWGSingboxTxt(content); err2 == nil {
			return end, nil
		}
		return nil, err
	}
	// "obfs=amneziawg&obfsParam={...}": the AmneziaWG values as a JSON object, as sing-box based
	// clients (Karing, ...) export them
	if param, ok := u.Params["obfsparam"]; ok {
		var values map[string]any
		if err := json.Unmarshal([]byte(param), &values); err != nil {
			return nil, fmt.Errorf("invalid obfsParam: %w", err)
		}
		for key, value := range values {
			key = normalizeStr(key)
			if _, exists := u.Params[key]; !exists {
				u.Params[key] = fmt.Sprint(value)
			}
		}
	}

	getInt := func(key string) int {
		if v, ok := u.Params[key]; ok {
			i, _ := strconv.Atoi(v)
			return i
		}
		return 0
	}

	getUint16 := func(key string) uint16 {
		if v, ok := u.Params[key]; ok {
			i, _ := strconv.Atoi(v)
			return uint16(i)
		}
		return 0
	}

	parsePrefixes := func(raw string) (badoption.Listable[netip.Prefix], error) {
		var out []netip.Prefix
		for _, s := range strings.Split(raw, ",") {
			if s != "" {
				p, err := netip.ParsePrefix(strings.TrimSpace(s))
				if err != nil {
					// a bare address is that one address: /32, or /128 for IPv6
					addr, err2 := netip.ParseAddr(strings.TrimSpace(s))
					if err2 != nil {
						return nil, fmt.Errorf("invalid %s: %w", raw, err)
					}
					p = netip.PrefixFrom(addr, addr.BitLen())
				}
				out = append(out, p)
			}
		}
		return badoption.Listable[netip.Prefix](out), nil
	}

	addresses, err := parsePrefixes(getOneOfN(u.Params, "", "ip", "address", "localaddress"))
	if err != nil {
		return nil, err
	}

	allowedIPs, err := parsePrefixes(getOneOfN(u.Params, "", "allowedips"))
	if err != nil {
		return nil, err
	}
	if len(allowedIPs) == 0 {
		allowedIPs = badoption.Listable[netip.Prefix]([]netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
		})
	}

	peer := T.AwgPeerOptions{
		Address:                     u.Hostname,
		Port:                        u.Port,
		PublicKey:                   getOneOfN(u.Params, "", "peerpublickey", "publickey", "pub", "peerpub", "peerpk"),
		PresharedKey:                getOneOfN(u.Params, "", "presharedkey", "psk"),
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: getUint16("keepalive"),
	}
	pk := getOneOfN(u.Params, "", "privatekey", "pk")
	if pk == "" {
		pk = u.Username
	}
	if pk == "" {
		return nil, errors.New("missing private_key")
	}
	if peer.PublicKey == "" {
		return nil, errors.New("missing peer_public_key")
	}
	opts := T.AwgEndpointOptions{

		PrivateKey: pk,
		Address:    addresses,

		Awg: T.AwgOptions{
			Jc:   getInt("jc"),
			Jmin: getInt("jmin"),
			Jmax: getInt("jmax"),

			S1: getInt("s1"),
			S2: getInt("s2"),
			S3: getInt("s3"),
			S4: getInt("s4"),
			H1: getOneOfN(u.Params, "", "h1"),
			H2: getOneOfN(u.Params, "", "h2"),
			H3: getOneOfN(u.Params, "", "h3"),
			H4: getOneOfN(u.Params, "", "h4"),

			I1: getOneOfN(u.Params, "", "i1"),
			I2: getOneOfN(u.Params, "", "i2"),
			I3: getOneOfN(u.Params, "", "i3"),
			I4: getOneOfN(u.Params, "", "i4"),
			I5: getOneOfN(u.Params, "", "i5"),
		},
		Peers: []T.AwgPeerOptions{peer},
	}
	if mtuStr, ok := u.Params["mtu"]; ok {
		if mtu, err := strconv.ParseUint(mtuStr, 10, 32); err == nil {
			opts.MTU = uint32(mtu)
		}
	}
	isAwg := opts.Awg.IsAvailble()
	wgopts := T.WireGuardEndpointOptions{
		PrivateKey: opts.PrivateKey,
		Address:    opts.Address,
		Peers: []T.WireGuardPeer{
			T.WireGuardPeer{
				Address:                     peer.Address,
				Port:                        peer.Port,
				PreSharedKey:                peer.PresharedKey,
				PublicKey:                   peer.PublicKey,
				AllowedIPs:                  T.LegacyListable[netip.Prefix](peer.AllowedIPs),
				PersistentKeepaliveInterval: peer.PersistentKeepaliveInterval,
			},
		},
		MTU:   uint32(toInt(getOneOfN(u.Params, "1280", "mtu"))),
		Noise: getWireGuardNoise(u.Params, false),
	}
	if isAwg {
		wgopts.MTU = opts.MTU
	}
	if reservedStr, ok := u.Params["reserved"]; ok {
		reservedParts := strings.Split(reservedStr, ",")
		for _, part := range reservedParts {
			num, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return nil, err // Handle the error appropriately
			}
			wgopts.Peers[0].Reserved = append(wgopts.Peers[0].Reserved, uint8(num))
		}
	}
	if workerStr, ok := u.Params["workers"]; ok {
		if workers, err := strconv.Atoi(workerStr); err == nil {
			wgopts.Workers = workers
		}
	}
	tag := u.Name
	if tag == "" {
		tag = "WG"
		if isAwg {
			tag = "AWG"
		}
	}
	return amneziaWireGuardEndpoint(tag, wgopts, opts.Awg), nil
}
