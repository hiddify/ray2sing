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

	return &T.Outbound{
		Tag:  decoded["ps"],
		Type: "xray",
		XrayOptions: T.XrayOutboundOptions{
			// DialerOptions: getDialerOptions(decoded),
			Fragment: getXrayFragmentOptions(decoded),
			XrayOutboundJson: &map[string]any{
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
				"mux":            getMuxOptionsXray(decoded),
			},
		},
	}, nil
}
