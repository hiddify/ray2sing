package ray2sing

import (
	T "github.com/sagernet/sing-box/option"

	
)

func ShadowsocksSingbox(shadowsocksUrl string) (*T.Outbound, error) {
	u, err := ParseUrl(shadowsocksUrl, 443)
	if err != nil {
		return nil, err
	}

	decoded := u.Params
	
	defaultMethod := u.Username
	pass:=u.Password
	if u.Password == "" {
		pass = u.Username
		defaultMethod = "none"
	}
	

	result := T.Outbound{
		Type: "shadowsocks",
		Tag:  u.Name,
		Options: &T.ShadowsocksOutboundOptions{
			ServerOptions: u.GetServerOption(),
			Method:        defaultMethod,
			Password:      pass,
			Plugin:        decoded["plugin"],
			PluginOptions: decoded["pluginopts"],
		},
	}

	return &result, nil
}
