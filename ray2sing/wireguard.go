package ray2sing

import (
	"net/netip"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

func WiregaurdSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	out := &T.Outbound{
		Type: "wireguard",
		Tag:  u.Name,
		WireGuardOptions: T.WireGuardOutboundOptions{
			ServerOptions: u.GetServerOption(),
			FakePackets:   u.Params["ifp"],
			FakePacketsSize: u.Params["ifps"],
			FakePacketsDelay: u.Params["ifpd"],
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

	if localAddress, err := getOneOf(u.Params, "localaddress", "ip"); err == nil {
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

	return out, nil
}
