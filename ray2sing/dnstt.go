package ray2sing

import (
	"strings"

	T "github.com/sagernet/sing-box/option"
)

func DnsttSingbox(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	uot := T.UDPOverTCPOptions{
		Enabled: getOneOfN(decoded, "", "uot") != "false" && getOneOfN(decoded, "", "uot") != "0",
	}
	return &T.Outbound{
		Tag:  u.Name + "§hide§",
		Type: "dnstt",
		Options: &T.DnsttOptions{
			DialerOptions:     getDialerOptions(decoded),
			PublicKey:         getOneOfN(decoded, "", "pubkey", "publickey", "serverpublickey"),
			Domain:            getOneOfN(decoded, "", "domain", "serveraddress", "address"),
			Resolvers:         strings.Split(getOneOfN(decoded, "", "resolver"), ","),
			TunnelPerResolver: toInt(getOneOfN(decoded, "4", "tunnel_per_resolver")),
			UDPOverTCP:        &uot,
		},
	}, nil
}
