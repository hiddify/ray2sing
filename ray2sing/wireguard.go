package ray2sing

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

func WiregaurdSingbox(url string) (*T.Outbound, error) {
	fmt.Println(url)
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

	out := &T.Outbound{
		Type: "wireguard",
		Tag:  u.Name,
		WireGuardOptions: T.WireGuardOutboundOptions{
			ServerOptions:    u.GetServerOption(),
			FakePackets:      fake_packet_count,
			FakePacketsSize:  fake_packet_size,
			FakePacketsDelay: fake_packet_delay,
			FakePacketsMode:  fake_packet_mode,
		},
	}

	if pk, err := getOneOf(u.Params, "privatekey", "pk"); err == nil {
		out.WireGuardOptions.PrivateKey = pk
	}

	if pub, err := getOneOf(u.Params, "peerpublickey", "publickey", "pub", "peerpub"); err == nil {
		out.WireGuardOptions.PeerPublicKey = pub
	}

	if psk, err := getOneOf(u.Params, "presharedkey", "psk"); err == nil {
		out.WireGuardOptions.PreSharedKey = psk
	}

	// Parse Workers
	if workerStr, ok := u.Params["workers"]; ok {
		if workers, err := strconv.Atoi(workerStr); err == nil {
			out.WireGuardOptions.Workers = workers
		}
	}

	if mtuStr, ok := u.Params["mtu"]; ok {
		if mtu, err := strconv.ParseUint(mtuStr, 10, 32); err == nil {
			out.WireGuardOptions.MTU = uint32(mtu)
		}
	}
	if reservedStr, ok := u.Params["reserved"]; ok {
		reservedParts := strings.Split(reservedStr, ",")

		for _, part := range reservedParts {
			num, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return nil, err // Handle the error appropriately
			}
			out.WireGuardOptions.Reserved = append(out.WireGuardOptions.Reserved, uint8(num))
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
			out.WireGuardOptions.LocalAddress = append(out.WireGuardOptions.LocalAddress, prefix)
		}
	}

	if out.WireGuardOptions.PrivateKey == "" { //it is warp
		return &T.Outbound{
			Type: "custom",
			Tag:  u.Name,
			CustomOptions: map[string]interface{}{
				"warp": map[string]interface{}{
					"key":                u.Username,
					"host":               out.WireGuardOptions.ServerOptions.Server,
					"port":               out.WireGuardOptions.ServerOptions.ServerPort,
					"fake_packets":       out.WireGuardOptions.FakePackets,
					"fake_packets_size":  out.WireGuardOptions.FakePacketsSize,
					"fake_packets_delay": out.WireGuardOptions.FakePacketsDelay,
					"fake_packets_mode":  out.WireGuardOptions.FakePacketsMode,
				},
			},
		}, nil
	}

	return out, nil
}
