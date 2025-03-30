package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func VmessXray(vmessURL string) (*T.Outbound, error) {
	decoded, err := decodeVmess(vmessURL)
	if err != nil {
		return nil, err
	}

	port := toInt16(decoded["port"], 443)

	if err != nil {
		return nil, err
	}

	// fmt.Printf("Port %v deco=%v", port, decoded)
	streamSettings, err := getStreamSettingsXray(decoded)

	if err != nil {
		return nil, err
	}

	// packetEncoding := decoded["packetencoding"]
	// if packetEncoding==""{
	// 	packetEncoding="xudp"
	// }
	security := "auto"
	if decoded["scy"] != "" {
		security = decoded["scy"]
	}
	res := map[string]any{

		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": decoded["add"],
					"port":    port,
					"users": []any{
						map[string]any{
							"id":       decoded["id"], // Change to your UUID.
							"security": security,
						},
					},
				},
			},
		},
		"tag":            decoded["ps"],
		"streamSettings": streamSettings,
	}
	if mux := getMuxOptionsXray(decoded); mux != nil {
		res["mux"] = mux
	}
	return makeXrayOptions(decoded, res)
}

// func VmessXray(vmessURL string) (*T.Outbound, error) {
// 	decoded, err := decodeVmess(vmessURL)
// 	if err != nil {
// 		return nil, err
// 	}

// 	port := toUInt16(decoded["port"], 443)

// 	if err != nil {
// 		return nil, err
// 	}

// 	// fmt.Printf("Port %v deco=%v", port, decoded)
// 	streamSettings, err := getStreamSettingsXray(decoded)

// 	if err != nil {
// 		return nil, err
// 	}

// 	// packetEncoding := decoded["packetencoding"]
// 	// if packetEncoding==""{
// 	// 	packetEncoding="xudp"
// 	// }
// 	security := "auto"
// 	if decoded["scy"] != "" {
// 		security = decoded["scy"]
// 	}
// 	xout := conf.OutboundDetourConfig{
// 		Tag:           decoded["ps"],
// 		Protocol:      "vmess",
// 		StreamSetting: streamSettings,
// 		MuxSettings:   getMuxOptionsXray(decoded),
// 		Settings: marshalJSON(conf.VMessOutboundConfig{
// 			Receivers: []*conf.VMessOutboundTarget{
// 				&conf.VMessOutboundTarget{
// 					Address: &conf.Address{Address: xnet.ParseAddress(decoded["add"])},
// 					Port:    port,
// 					Users: []json.RawMessage{
// 						*marshalJSON(map[string]string{
// 							"id":       decoded["id"],
// 							"security": security,
// 						}),
// 					},
// 				},
// 			},
// 		}),
// 	}
// 	return makeXrayOptions(decoded, &xout)
// }
