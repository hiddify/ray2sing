package ray2sing

import (
	"strings"

	T "github.com/sagernet/sing-box/option"
)

func ShadowsocksSingbox(shadowsocksUrl string) (*T.Outbound, error) {
	u, err := ParseUrl(shadowsocksUrl, 443)
	if err != nil {
		return nil, err
	}

	decoded := u.Params

	defaultMethod := u.Username
	pass := u.Password
	if u.Password == "" {
		pass = u.Username
		defaultMethod = "none"
	}

	// SIP002: plugin=<name>;<opts>, e.g. "v2ray-plugin;mode=websocket;path=/p;host=h;tls"
	plugin, pluginOpts, _ := strings.Cut(decoded["plugin"], ";")
	if pluginOpts == "" {
		pluginOpts = decoded["pluginopts"]
	}

	options := &T.ShadowsocksOutboundOptions{
		ServerOptions: u.GetServerOption(),
		Method:        defaultMethod,
		Password:      pass,
		Plugin:        plugin,
		PluginOptions: pluginOpts,
	}
	if toBool(decoded["uot"], false) {
		options.UDPOverTCP = &T.UDPOverTCPOptions{Enabled: true}
	}

	return &T.Outbound{
		Type:    "shadowsocks",
		Tag:     u.Name,
		Options: options,
	}, nil
}
