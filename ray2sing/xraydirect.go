package ray2sing

import (
	"strings"

	T "github.com/sagernet/sing-box/option"
)

func DirectXray(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// packetEncoding := decoded["packetencoding"]
	// if packetEncoding==""{
	// 	packetEncoding="xudp"
	// }
	frag, err := getOneOf(decoded, "frg", "fragment")
	fragdata := map[string]any{}
	if err != nil && frag != "" {
		frags := strings.Split(frag, ",")
		fragdata = map[string]any{
			"packets":  frags[0],
			"length":   frags[1],
			"interval": frags[2],
		}
	}
	return &T.Outbound{
		Tag:  u.Name,
		Type: "xray",
		XrayOptions: T.XrayOutboundOptions{
			Fragment: getXrayFragmentOptions(decoded),
			// DialerOptions: getDialerOptions(decoded),
			XrayOutboundJson: &map[string]any{
				"protocol":       "freedom",
				"domainStrategy": "AsIs",
				"settings": map[string]any{
					"fragment": fragdata,
				},
				"streamSettings": map[string]any{
					"sockopt": map[string]any{
						"tcpNoDelay":       true,
						"tcpKeepAliveIdle": 100,
					},
				},
				"tag": u.Name,
			},
		},
	}, nil
}
