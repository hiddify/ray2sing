package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func WarpSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}

	out := &T.Outbound{
		Type: "custom",
		Tag:  u.Name,
		Options: &map[string]any{
			"warp": map[string]any{
				"key":                u.Username,
				"host":               u.Hostname,
				"port":               u.Port,
				"fake_packets":       u.Params["ifp"],
				"fake_packets_size":  u.Params["ifps"],
				"fake_packets_delay": u.Params["ifpd"],
				"fake_packets_mode":  u.Params["ifpm"],
			},
		},
	}
	if out.Tag == "" {
		out.Tag = "WARP"
	}
	return out, nil
}
