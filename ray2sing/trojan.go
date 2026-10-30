package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func TrojanSingbox(trojanURL string) (*T.Outbound, error) {
	u, err := ParseUrl(trojanURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// trojan is TLS unless the link says otherwise, as in Xray and v2rayN
	if _, ok := decoded["security"]; !ok && decoded["tls"] == "" {
		decoded["security"] = "tls"
	}

	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}

	tlsOptions := getTLSOptions(decoded)
	if tlsOptions.TLS != nil && isReality(decoded) {
		tlsOptions.TLS.Reality = &T.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: decoded["pbk"],
			ShortID:   decoded["sid"],
		}
	}

	return &T.Outbound{
		Tag:  u.Name,
		Type: "trojan",
		Options: &T.TrojanOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			Password:                    u.Username,
			OutboundTLSOptionsContainer: tlsOptions,
			Transport:                   transportOptions,
			Multiplex:                   getMuxOptions(decoded),
		},
	}, nil
}
