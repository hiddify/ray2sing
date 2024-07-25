package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func VlessXray(vlessURL string) (*T.Outbound, error) {
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
			XrayOutboundJson: map[string]any{

				"protocol": "vless",
				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address": decoded["host"],
							"port":    decoded["port"],
							"users": []any{
								map[string]string{
									"id":         u.Username, // Change to your UUID.
									"encryption": "none",
									"flow":       decoded["flow"],
								},
							},
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
