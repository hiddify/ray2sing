package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func TrojanSingbox(trojanURL string) (*T.Outbound, error) {
	u, err := ParseUrl(trojanURL)
	if err != nil {
		return nil, err
	}
	decoded := u.Params

	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}

	return &T.Outbound{
		Tag:  u.Name,
		Type: "trojan",
		TrojanOptions: T.TrojanOutboundOptions{
			DialerOptions: T.DialerOptions{},
			ServerOptions: u.GetServerOption(),
			Password:      u.Username,
			TLS:           getTLSOptions(decoded),
			Transport:     transportOptions,
		},
	}, nil
}
