package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func VlessSingbox(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// fmt.Printf("Port %v deco=%v", port, decoded)
	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}

	tlsOptions := getTLSOptions(decoded)
	if tlsOptions != nil {
		if security := decoded["security"]; security == "reality" {
			tlsOptions.Reality = &T.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: decoded["pbk"],
				ShortID:   decoded["sid"],
			}
		}
	}

	packetEncoding := decoded["packetEncoding"]
	// if packetEncoding==""{
	// 	packetEncoding="xudp"
	// }

	return &T.Outbound{
		Tag:  u.Name,
		Type: "vless",
		VLESSOptions: T.VLESSOutboundOptions{
			DialerOptions:  getDialerOptions(decoded),
			ServerOptions:  u.GetServerOption(),
			UUID:           u.Username,
			PacketEncoding: &packetEncoding,
			Flow:           decoded["flow"],
			TLS:            tlsOptions,
			Transport:      transportOptions,
		},
	}, nil
}
