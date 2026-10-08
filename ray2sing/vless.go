package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func VlessSingbox(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
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
	if tlsOptions.TLS != nil {
		if security := decoded["security"]; security == "reality" {
			tlsOptions.TLS.Reality = &T.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: decoded["pbk"],
				ShortID:   decoded["sid"],
			}
		}
	}

	// VLESS encryption (e.g. mlkem768x25519plus...); "none" is the plain protocol
	encryption := decoded["encryption"]
	if encryption == "none" {
		encryption = ""
	}

	packetEncoding := decoded["packetencoding"]
	if packetEncoding == "" {
		packetEncoding = "xudp"
	}

	return &T.Outbound{
		Tag:  u.Name,
		Type: "vless",
		Options: &T.VLESSOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			UUID:                        u.Username,
			PacketEncoding:              &packetEncoding,
			Flow:                        decoded["flow"],
			Encryption:                  encryption,
			OutboundTLSOptionsContainer: tlsOptions,
			Transport:                   transportOptions,
			Multiplex:                   getMuxOptions(decoded),
		},
	}, nil
}
