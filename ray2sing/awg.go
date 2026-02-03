package ray2sing

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func AWGSingboxTxt(content string) (*T.Endpoint, error) {

	var (
		privateKey                     string
		addresses                      []netip.Prefix
		jc, jmin, jmax                 int
		s1, s2, s3, s4                 int
		h1, h2, h3, h4, i1, i2, i3, i4 string

		peer T.AwgPeerOptions
	)

	section := ""

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
			case "PrivateKey":
				privateKey = val

			case "Address":
				pfx, err := netip.ParsePrefix(val)
				if err != nil {
					return nil, fmt.Errorf("invalid Address: %w", err)
				}
				addresses = append(addresses, pfx)

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
			}

		case "peer":
			switch key {
			case "PublicKey":
				peer.PublicKey = val
			case "PresharedKey":
				peer.PresharedKey = val

			case "AllowedIPs":
				pfx, err := netip.ParsePrefix(val)
				if err != nil {
					return nil, fmt.Errorf("invalid AllowedIPs: %w", err)
				}
				peer.AllowedIPs = badoption.Listable[netip.Prefix]{pfx}

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
			}
		}
	}

	if privateKey == "" {
		return nil, errors.New("missing PrivateKey")
	}

	if peer.Address == "" || peer.Port == 0 {
		return nil, errors.New("missing peer Endpoint")
	}
	if jc+jmin+jmax+s1+s2+s3+s4 == 0 && h1+h2+h3+h4+i1+i2+i3+i4 == "" {
		fmt.Println(">>out", C.TypeAwg)
		return &T.Endpoint{
			Type: C.TypeWireGuard,
			Tag:  "wiregaurd",
			Options: &T.WireGuardEndpointOptions{
				PrivateKey: privateKey,
				Address:    badoption.Listable[netip.Prefix](addresses),
				Peers: []T.WireGuardPeer{
					T.WireGuardPeer{
						Address:                     peer.Address,
						Port:                        peer.Port,
						PreSharedKey:                peer.PresharedKey,
						PublicKey:                   peer.PublicKey,
						AllowedIPs:                  peer.AllowedIPs,
						PersistentKeepaliveInterval: peer.PersistentKeepaliveInterval,
					},
				},
			},
		}, nil
	}

	out := &T.Endpoint{
		Type: C.TypeAwg,
		Tag:  "awg", // adjust if you derive tag elsewhere
		Options: &T.AwgEndpointOptions{

			PrivateKey: privateKey,
			Address:    badoption.Listable[netip.Prefix](addresses),

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

			Peers: []T.AwgPeerOptions{peer},
		},
	}

	return out, nil
}

func AWGSingbox(raw string) (*T.Endpoint, error) {

	u, err := ParseUrl(raw, 0)
	fmt.Println("u", len(u.Params), "e", err)
	if err != nil || len(u.Params) == 0 {
		splt := strings.SplitN(raw, "://", 2)
		if len(splt) == 2 {
			d, _ := decodeBase64IfNeeded(splt[1])

			if end, err2 := AWGSingboxTxt(d); err2 == nil {
				return end, nil
			}
		}
		return nil, err
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

	parsePrefixes := func(key string) (badoption.Listable[netip.Prefix], error) {
		raw, ok := u.Params[key]
		if !ok || raw == "" {
			return nil, nil
		}

		var out []netip.Prefix
		for _, s := range strings.Split(raw, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("invalid %s: %w", key, err)
			}
			out = append(out, p)
		}
		return badoption.Listable[netip.Prefix](out), nil
	}

	addresses, err := parsePrefixes("address")
	if err != nil {
		return nil, err
	}

	allowedIPs, err := parsePrefixes("allowedips")
	if err != nil {
		return nil, err
	}

	peer := T.AwgPeerOptions{
		Address: u.Hostname,
		Port:    u.Port,

		PublicKey:                   getOneOfN(u.Params, "", "peerpublickey"),
		PresharedKey:                getOneOfN(u.Params, "", "preshared_key"),
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: getUint16("keepalive"),
	}
	pk := getOneOfN(u.Params, "", "privatekey")
	if pk == "" {
		return nil, errors.New("missing private_key")
	}
	if peer.PublicKey == "" {
		return nil, errors.New("missing peer_public_key")
	}
	out := &T.Endpoint{
		Type: C.TypeAwg,
		Tag:  u.Name,
		Options: &T.AwgEndpointOptions{

			PrivateKey: pk,
			Address:    addresses,

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

			Peers: []T.AwgPeerOptions{peer},
		},
	}

	if out.Tag == "" {
		out.Tag = "AWG"
	}

	return out, nil
}
