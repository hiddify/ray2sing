package ray2sing

import (
	"net/netip"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func WiregaurdSingbox(url string) (*T.Outbound, error) {
	// fmt.Println(url)
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	fake_packet_count, err := getOneOf(u.Params, "ifp", "wnoisecount")
	if err != nil {
		return nil, err
	}
	fake_packet_delay, err := getOneOf(u.Params, "ifpd", "wnoisedelay")
	if err != nil {
		return nil, err
	}

	fake_packet_size, err := getOneOf(u.Params, "ifps", "wpayloadsize")
	if err != nil {
		return nil, err
	}
	fake_packet_mode := u.Params["ifpm"]
	if wnoise, ok := u.Params["wnoise"]; ok {
		switch wnoise {
		case "quic":
			fake_packet_mode = "m4"
		}
	}
	peer := T.WireGuardPeer{
		Address: u.Hostname,
		Port:    u.Port,
		WireGuardHiddify: T.WireGuardHiddify{
			FakePackets:      fake_packet_count,
			FakePacketsSize:  fake_packet_size,
			FakePacketsDelay: fake_packet_delay,
			FakePacketsMode:  fake_packet_mode,
		},
	}
	opts := T.WireGuardEndpointOptions{

		Peers: []T.WireGuardPeer{
			peer,
		},
		// ServerOptions:    u.GetServerOption(),

	}
	if pk, err := getOneOf(u.Params, "privatekey", "pk"); err == nil {
		opts.PrivateKey = pk
	}

	if pub, err := getOneOf(u.Params, "peerpublickey", "publickey", "pub", "peerpub"); err == nil {
		peer.PublicKey = pub
	}

	if psk, err := getOneOf(u.Params, "presharedkey", "psk"); err == nil {
		peer.PreSharedKey = psk
	}

	// Parse Workers
	if workerStr, ok := u.Params["workers"]; ok {
		if workers, err := strconv.Atoi(workerStr); err == nil {
			opts.Workers = workers
		}
	}

	if mtuStr, ok := u.Params["mtu"]; ok {
		if mtu, err := strconv.ParseUint(mtuStr, 10, 32); err == nil {
			opts.MTU = uint32(mtu)
		}
	}
	if reservedStr, ok := u.Params["reserved"]; ok {
		reservedParts := strings.Split(reservedStr, ",")

		for _, part := range reservedParts {
			num, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return nil, err // Handle the error appropriately
			}
			peer.Reserved = append(peer.Reserved, uint8(num))
		}
	}

	if localAddress, err := getOneOf(u.Params, "localaddress", "ip", "address"); err == nil {
		localAddressParts := strings.Split(localAddress, ",")
		for _, part := range localAddressParts {
			if !strings.Contains(part, "/") {
				part += "/24"
			}
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, err // Handle the error appropriately
			}
			opts.Address = append(opts.Address, prefix)
		}
	}

	if opts.PrivateKey == "" { //it is warp
		return &T.Outbound{
			Type: C.TypeCustom,
			Tag:  u.Name,
			Options: &map[string]any{
				"warp": map[string]any{
					"key":                u.Username,
					"host":               u.Hostname,
					"port":               u.Port,
					"fake_packets":       fake_packet_count,
					"fake_packets_size":  fake_packet_size,
					"fake_packets_delay": fake_packet_delay,
					"fake_packets_mode":  fake_packet_mode,
				},
			},
		}, nil
	}
	out := &T.Outbound{
		Type: "wireguard",
		Tag:  u.Name,

		Options: &opts,
	}

	return out, nil
}
