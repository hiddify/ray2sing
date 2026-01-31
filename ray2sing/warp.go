package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func WarpSingbox(url string) (*T.Endpoint, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}

	out := &T.Endpoint{
		Type: C.TypeWARP,
		Tag:  u.Name,
		Options: &T.WireGuardWARPEndpointOptions{
			ServerOptions: T.ServerOptions{
				Server:     u.Hostname,
				ServerPort: u.Port,
			},
			UniqueIdentifier: u.Username,
			WireGuardHiddify: T.WireGuardHiddify{
				FakePackets:      u.Params["ifp"],
				FakePacketsSize:  u.Params["ifps"],
				FakePacketsDelay: u.Params["ifpd"],
				FakePacketsMode:  u.Params["ifpm"],
			},
		},
	}

	if out.Tag == "" {
		out.Tag = "WARP"
	}
	return out, nil
}
