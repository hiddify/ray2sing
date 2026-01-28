package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func DirectSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}

	out := &T.Outbound{
		Type: C.TypeDirect,
		Tag:  u.Name,
		Options: &T.DirectOutboundOptions{
			DialerOptions: getDialerOptions(u.Params),
		},
	}
	return out, nil
}
