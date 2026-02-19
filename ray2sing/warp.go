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
	// fmt.Println(u.Username, "-", u.Password, "-", u.Params)
	out := T.Endpoint{
		Type: C.TypeWARP,
		Tag:  u.Name,
		Options: &T.WireGuardWARPEndpointOptions{
			ServerOptions: T.ServerOptions{
				Server:     u.Hostname,
				ServerPort: u.Port,
			},
			UniqueIdentifier: u.Username,
			Noise:            getWireGuardNoise(u.Params, false),
			MTU:              uint32(toInt(getOneOfN(u.Params, "1280", "mtu"))),
		},
	}

	if out.Tag == "" {
		out.Tag = "WARP"
	}
	return &out, nil
}
