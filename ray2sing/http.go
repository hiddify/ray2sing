package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func HttpSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	if u.Port == 0 { // a web page or a subscription link, such as https://example.com/sub.txt
		return nil, E.New("not an HTTP proxy, it has no port: ", url)
	}
	opts := T.HTTPOutboundOptions{
		ServerOptions: u.GetServerOption(),
		Username:      u.Username,
		Password:      u.Password,
	}
	out := &T.Outbound{
		Type:    C.TypeHTTP,
		Tag:     u.Name,
		Options: &opts,
	}
	if _, err := getOneOf(u.Params, "tls", "sni", "insecure"); err == nil {
		opts.OutboundTLSOptionsContainer.TLS = &T.OutboundTLSOptions{
			Enabled: true,
		}
	}
	if sni, err := getOneOf(u.Params, "sni"); err == nil {
		opts.OutboundTLSOptionsContainer.TLS.ServerName = sni
	}
	if insecure, err := getOneOf(u.Params, "insecure"); err == nil {
		opts.OutboundTLSOptionsContainer.TLS.Insecure = insecure != "0"
	}
	if path, err := getOneOf(u.Params, "path"); err == nil {
		opts.Path = path
	}
	// if net, err := getOneOf(u.Params, "net", "network"); err == nil {
	// 	out.SocksOptions.Network= net
	// }
	return out, nil
}

func HttpsSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	if u.Port == 0 { // a web page or a subscription link, such as https://example.com/sub.txt
		return nil, E.New("not an HTTP proxy, it has no port: ", url)
	}
	opts := T.HTTPOutboundOptions{
		ServerOptions: u.GetServerOption(),
		Username:      u.Username,
		Password:      u.Password,
	}
	out := &T.Outbound{
		Type:    C.TypeHTTP,
		Tag:     u.Name,
		Options: &opts,
	}
	opts.OutboundTLSOptionsContainer.TLS = &T.OutboundTLSOptions{
		Enabled: true,
	}
	if sni, err := getOneOf(u.Params, "sni"); err == nil {
		opts.OutboundTLSOptionsContainer.TLS.ServerName = sni
	}
	if insecure, err := getOneOf(u.Params, "insecure"); err == nil {
		opts.OutboundTLSOptionsContainer.TLS.Insecure = insecure != "0"
	}

	if path, err := getOneOf(u.Params, "path"); err == nil {
		opts.Path = path
	}

	// if net, err := getOneOf(u.Params, "net", "network"); err == nil {
	// 	out.SocksOptions.Network= net
	// }
	return out, nil
}
