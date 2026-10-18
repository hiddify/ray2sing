package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

// SnellSingbox parses snell://psk@host:port/?version=4&obfs=http|tls&obfs-host=...#name
// https://manual.nssurge.com/policies/snell.html
func SnellSingbox(snellURL string) (*T.Outbound, error) {
	u, err := ParseUrl(snellURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// snell://psk@host (legacy) or snell://userkey@host?psk=... (panel multi-user)
	psk := decoded["psk"]
	userKey := getOneOfN(decoded, "", "userkey")
	if psk == "" {
		psk = u.Username
	} else if userKey == "" && u.Username != "" {
		userKey = u.Username
	}
	options := &T.SnellOutboundOptions{
		Version: toInt(getOneOfN(decoded, "4", "version")),
		AbstractSnellOutboundOptions: T.AbstractSnellOutboundOptions{
			DialerOptions: getDialerOptions(decoded),
			ServerOptions: u.GetServerOption(),
			PSK:           psk,
			UserKey:       userKey,
			Reuse:         toBool(decoded["reuse"], false),
		},
	}
	switch options.Version {
	case 4:
		options.ObfsOptions = T.SnellObfsClientOptions{
			ObfsMode: getOneOfN(decoded, "", "obfs", "obfsmode"),
			ObfsHost: getOneOfN(decoded, "", "obfshost"),
		}
	case 6:
		options.V6Options = T.SnellV6Options{Mode: decoded["mode"]}
	}
	return &T.Outbound{
		Type:    C.TypeSnell,
		Tag:     u.Name,
		Options: options,
	}, nil
}
