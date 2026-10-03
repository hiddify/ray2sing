package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

// AnyTLSSingbox parses anytls://password@host:port/?sni=...&insecure=0|1#name
// https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md
func AnyTLSSingbox(anytlsURL string) (*T.Outbound, error) {
	u, err := ParseUrl(anytlsURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	password := u.Username
	if u.Password != "" {
		password += ":" + u.Password
	}
	sni := getOneOfN(decoded, "", "sni", "peer")
	if sni == "" && !isIPOnly(u.Hostname) {
		sni = u.Hostname
	}
	tls := &T.OutboundTLSOptions{
		Enabled:    true,
		ServerName: sni,
		Insecure:   toBool(decoded["insecure"], false) || toBool(decoded["allowinsecure"], false),
	}
	if fp := decoded["fp"]; fp != "" {
		tls.UTLS = &T.OutboundUTLSOptions{Enabled: true, Fingerprint: fp}
	}
	return &T.Outbound{
		Type: C.TypeAnyTLS,
		Tag:  u.Name,
		Options: &T.AnyTLSOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{TLS: tls},
			Password:                    password,
		},
	}, nil
}
