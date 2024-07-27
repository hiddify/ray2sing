package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func TrojanXray(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// fmt.Printf("Port %v deco=%v", port, decoded)
	streamSettings, err := getStreamSettingsXray(decoded)
	if err != nil {
		return nil, err
	}

	// packetEncoding := decoded["packetencoding"]
	// if packetEncoding==""{
	// 	packetEncoding="xudp"
	// }

	return &T.Outbound{
		Tag:  u.Name,
		Type: "xray",
		XrayOptions: T.XrayOutboundOptions{
			// DialerOptions: getDialerOptions(decoded),
			Fragment: getXrayFragmentOptions(decoded),
			XrayOutboundJson: &map[string]any{
				"protocol": "trojan",

				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address":  u.Hostname,
							"port":     u.Port,
							"password": u.Username,
						},
					},
				},
				"tag":            u.Name,
				"streamSettings": streamSettings,
				"mux":            getMuxOptionsXray(decoded),
			},
		},
	}, nil
}
