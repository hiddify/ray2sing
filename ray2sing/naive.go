package ray2sing

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func NaiveSingbox(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	if decoded["security"] == "" {
		decoded["security"] = "tls"
	}

	// fmt.Printf("Port %v deco=%v", port, decoded)
	tlsOptions := getTLSOptions(decoded)
	if tlsOptions.TLS != nil {
		if security := decoded["security"]; security == "reality" {
			tlsOptions.TLS.Reality = &T.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: decoded["pbk"],
				ShortID:   decoded["sid"],
			}
		}
	}
	uot := T.UDPOverTCPOptions{
		Enabled: getOneOfN(decoded, "", "uot") == "false" || getOneOfN(decoded, "", "uot") == "0",
	}

	return &T.Outbound{
		Tag:  u.Name,
		Type: C.TypeNaive,
		Options: &T.NaiveOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			Username:                    u.Username,
			Password:                    u.Password,
			InsecureConcurrency:         toInt(getOneOfN(decoded, "0", "insecure_concurrency")),
			ExtraHeaders:                GetHttpHeaders(getOneOfN(decoded, "", "header")),
			QUIC:                        getOneOfN(decoded, "", "quic") != "",
			QUICCongestionControl:       getOneOfN(decoded, "", "quic_congestion_control"),
			OutboundTLSOptionsContainer: tlsOptions,
			UDPOverTCP:                  &uot,
		},
	}, nil
}

func GetHttpHeaders(header string) badoption.HTTPHeader {
	kvs := strings.Split(header, ",")
	res := badoption.HTTPHeader{}

	for _, raw := range kvs {
		splt := strings.SplitN(raw, ":", 2)
		if len(splt) != 2 {
			continue
		}
		k, v := splt[0], splt[1]
		if _, ok := res[k]; !ok {
			res[k] = []string{}
		}
		res[k] = append(res[k], v)
	}
	return res
}
