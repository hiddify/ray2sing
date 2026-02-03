package ray2sing

import (
	"strconv"

	"github.com/sagernet/wireguard-go/hiddify"
)

func convertRange(s string) hiddify.Range {
	r := hiddify.Range{}
	r.UnmarshalJSON([]byte(strconv.Quote(s)))
	return r
}
func getWireGuardNoise(d map[string]string) hiddify.NoiseOptions {
	fake_packet_count := convertRange(getOneOfN(d, "", "ifp", "wnoisecount"))

	fake_packet_delay := convertRange(getOneOfN(d, "", "ifpd", "wnoisedelay"))

	fake_packet_size := convertRange(getOneOfN(d, "", "ifps", "wpayloadsize"))

	fake_packet_mode := d["ifpm"]
	if wnoise, ok := d["wnoise"]; ok {
		switch wnoise {
		case "quic":
			fake_packet_mode = "m4"
		}
	}
	return hiddify.NoiseOptions{
		FakePacket: hiddify.FakePacketOptions{
			Count: fake_packet_count,
			Size:  fake_packet_size,
			Delay: fake_packet_delay,
			Mode:  fake_packet_mode,
		},
	}
}

// func WiregaurdSingbox(url string) (*T.Endpoint, error) {
// 	// fmt.Println(url)
// 	u, err := ParseUrl(url, 0)
// 	if err != nil {
// 		return nil, err
// 	}

// 	peer := T.WireGuardPeer{
// 		Address: u.Hostname,
// 		Port:    u.Port,
// 	}
// 	opts := T.WireGuardEndpointOptions{

// 		Peers: []T.WireGuardPeer{
// 			peer,
// 		},
// 		Noise: getWireGuardNoise(u.Params),
// 		// ServerOptions:    u.GetServerOption(),

// 	}
// 	if pk, err := getOneOf(u.Params, "privatekey", "pk"); err == nil {
// 		opts.PrivateKey = pk
// 	}

// 	if pub, err := getOneOf(u.Params, "peerpublickey", "publickey", "pub", "peerpub"); err == nil {
// 		peer.PublicKey = pub
// 	}

// 	if psk, err := getOneOf(u.Params, "presharedkey", "psk"); err == nil {
// 		peer.PreSharedKey = psk
// 	}

// 	// Parse Workers
// 	if workerStr, ok := u.Params["workers"]; ok {
// 		if workers, err := strconv.Atoi(workerStr); err == nil {
// 			opts.Workers = workers
// 		}
// 	}

// 	if mtuStr, ok := u.Params["mtu"]; ok {
// 		if mtu, err := strconv.ParseUint(mtuStr, 10, 32); err == nil {
// 			opts.MTU = uint32(mtu)
// 		}
// 	}
// 	if reservedStr, ok := u.Params["reserved"]; ok {
// 		reservedParts := strings.Split(reservedStr, ",")

// 		for _, part := range reservedParts {
// 			num, err := strconv.ParseUint(part, 10, 8)
// 			if err != nil {
// 				return nil, err // Handle the error appropriately
// 			}
// 			peer.Reserved = append(peer.Reserved, uint8(num))
// 		}
// 	}

// 	if localAddress, err := getOneOf(u.Params, "localaddress", "ip", "address"); err == nil {
// 		localAddressParts := strings.Split(localAddress, ",")
// 		for _, part := range localAddressParts {
// 			if !strings.Contains(part, "/") {
// 				part += "/24"
// 			}
// 			prefix, err := netip.ParsePrefix(part)
// 			if err != nil {
// 				return nil, err // Handle the error appropriately
// 			}
// 			opts.Address = append(opts.Address, prefix)
// 		}
// 	}

// 	if opts.PrivateKey == "" { //it is warp
// 		return &T.Endpoint{
// 			Type: C.TypeWARP,
// 			Tag:  u.Name,
// 			Options: &T.WireGuardWARPEndpointOptions{
// 				ServerOptions: T.ServerOptions{
// 					Server:     u.Hostname,
// 					ServerPort: u.Port,
// 				},
// 				UniqueIdentifier: u.Username,
// 				Noise:            getWireGuardNoise(u.Params),
// 			},
// 		}, nil
// 	}
// 	out := &T.Endpoint{
// 		Type: "wireguard",
// 		Tag:  u.Name,

// 		Options: &opts,
// 	}

// 	return out, nil
// }
