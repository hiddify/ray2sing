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

			PrivateKey:    u.Params["pk"],
			PeerPublicKey: u.Params["peer_pub"],
			PreSharedKey:  u.Params["psk"],
			FakePackets:   u.Params["ifp"],
		},
	}
	if pk, ok := u.Params["private_key"]; ok {
		out.WireGuardOptions.PrivateKey = pk
	}
	if pk, ok := u.Params["privateKey"]; ok {
		out.WireGuardOptions.PrivateKey = pk
	}
	if pub, ok := u.Params["peer_public_key"]; ok {
		out.WireGuardOptions.PeerPublicKey = pub
	}
	if pub, ok := u.Params["peerPublicKey"]; ok {
		out.WireGuardOptions.PeerPublicKey = pub
	}
	if psk, ok := u.Params["pre_shared_key"]; ok {
		out.WireGuardOptions.PreSharedKey = psk
	}
	if psk, ok := u.Params["presharedKey"]; ok {
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
	if localAddressStr, ok := u.Params["local_address"]; ok {
		localAddressParts := strings.Split(localAddressStr, ",")
		for _, part := range localAddressParts {
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, err // Handle the error appropriately
			}
			out.WireGuardOptions.LocalAddress = append(out.WireGuardOptions.LocalAddress, prefix)
		}
	}

	return out, nil
}
