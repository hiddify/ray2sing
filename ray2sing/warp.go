package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func WarpSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url)
	if err != nil {
		return nil, err
	}
	out := &T.Outbound{
		Type: "custom",
		Tag:  u.Name,
		CustomOptions: map[string]interface{}{
			"warp": map[string]interface{}{
				"key":          u.Username,
				"host":         u.Hostname,
				"port":         u.Port,
				"fake_packets": u.Params["ifp"],
			},
		},
	}
	return out, nil
}
