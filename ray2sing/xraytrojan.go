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

	return makeXrayOptions(decoded, map[string]any{

		"protocol": "trojan",

		"settings": map[string]any{
			"servers": []any{
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
	})
}

// func TrojanXray(vlessURL string) (*T.Outbound, error) {
// 	u, err := ParseUrl(vlessURL, 443)
// 	if err != nil {
// 		return nil, err
// 	}
// 	decoded := u.Params
// 	// fmt.Printf("Port %v deco=%v", port, decoded)
// 	streamSettings, err := getStreamSettingsXray(decoded)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// packetEncoding := decoded["packetencoding"]
// 	// if packetEncoding==""{
// 	// 	packetEncoding="xudp"
// 	// }
// 	xout := conf.OutboundDetourConfig{
// 		Tag:           u.Name,
// 		StreamSetting: streamSettings,
// 		MuxSettings:   getMuxOptionsXray(decoded),
// 		Protocol:      "trojan",
// 		Settings: marshalJSON(conf.TrojanClientConfig{
// 			Servers: []*conf.TrojanServerTarget{
// 				&conf.TrojanServerTarget{
// 					Address:  &conf.Address{Address: xnet.ParseAddress(u.Hostname)},
// 					Port:     u.Port,
// 					Password: u.Username,
// 					Flow:     decoded["flow"],
// 				},
// 			},
// 		}),
// 	}

// 	return makeXrayOptions(decoded, &xout)

// 	// 	XrayOptions: T.XrayOutboundOptions{
// 	// 		// DialerOptions: getDialerOptions(decoded),

// 	// 		XrayOutboundJson: &map[string]any{
// 	// 			"protocol": "trojan",

// 	// 			"settings": map[string]any{
// 	// 				"servers": []any{
// 	// 					map[string]any{
// 	// 						"address":  u.Hostname,
// 	// 						"port":     u.Port,
// 	// 						"password": u.Username,
// 	// 					},
// 	// 				},
// 	// 			},
// 	// 			"tag":            u.Name,
// 	// 			"streamSettings": streamSettings,
// 	// 			"mux":            getMuxOptionsXray(decoded),
// 	// 		},
// 	// 	},
// 	// }, nil
// }
