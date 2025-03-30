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
	user := map[string]string{
		"id":         u.Username, // Change to your UUID.
		"encryption": "none",
	}
	if flow := decoded["flow"]; flow != "" {
		user["flow"] = flow
	}

	res := map[string]any{

		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{
				user,
			},
		},
		"tag":            u.Name,
		"streamSettings": streamSettings,
	}
	if mux := getMuxOptionsXray(decoded); mux != nil {
		res["mux"] = mux
	}
	return makeXrayOptions(decoded, res)

}

// func VlessXray(vlessURL string) (*T.Outbound, error) {
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
// 	// vnext :=

// 	xout := conf.OutboundDetourConfig{
// 		Tag:           u.Name,
// 		StreamSetting: streamSettings,
// 		MuxSettings:   getMuxOptionsXray(decoded),
// 		Protocol:      "vless",
// 		Settings: marshalJSON(conf.VLessOutboundConfig{
// 			Vnext: []*conf.VLessOutboundVnext{
// 				&conf.VLessOutboundVnext{
// 					Address: &conf.Address{Address: xnet.ParseAddress(u.Hostname)},
// 					Port:    u.Port,
// 					Users: []json.RawMessage{
// 						*marshalJSON(map[string]string{
// 							"id":         u.Username, // Ensure this is a valid UUID.
// 							"encryption": "none",
// 							"flow":       decoded["flow"],
// 						}),
// 					},
// 				},
// 			},
// 		},
// 		),
// 		// DialerOptions: getDialerOptions(decoded),
// 		// Fragment: getXrayFragmentOptions(decoded),
// 		// XrayOutboundJson: &map[string]any

// 	}

// 	return makeXrayOptions(decoded, &xout)

// }
