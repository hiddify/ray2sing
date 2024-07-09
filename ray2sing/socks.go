package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func SocksSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}

	out := &T.Outbound{
		Type: C.TypeSOCKS,
		Tag:  u.Name,
		SocksOptions: T.SocksOutboundOptions{
			ServerOptions: u.GetServerOption(),
			Username:      u.Username,
			Password:      u.Password,
		},
	}
	if version, err := getOneOf(u.Params, "v", "ver", "version"); err == nil {
		out.SocksOptions.Version = version
	}
	// if net, err := getOneOf(u.Params, "net", "network"); err == nil {
	// 	out.SocksOptions.Network= net
	// }
	return out, nil
}
