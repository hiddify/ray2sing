package ray2sing

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

func parseWireguard(inputURL string) (result map[string]string, err error) {
	return nil, fmt.Errorf("Not Implemented")
}

func WiregaurdSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url)
	if err != nil {
		return nil, err
	}
	out := &T.Outbound{
		Type: "wireguard",
		Tag:  u.Name,
		WireGuardOptions: T.WireGuardOutboundOptions{
			ServerOptions: u.GetServerOption(),

			PrivateKey:    u.Params["pk"],
			PeerPublicKey: u.Params["peer_pk"],
			PreSharedKey:  u.Params["pre_shared_key"],
		},
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
