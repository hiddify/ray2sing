package ray2sing

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func MieruSingbox(uri string) (*T.Outbound, error) {
	u, err := ParseUrl(uri, 0)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// mierus://baozi:manlianpenfen@1.2.3.4?handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_HIGH&port=6666&port=9998-9999&port=6489&port=4896&profile=default&protocol=TCP&protocol=TCP&protocol=UDP&protocol=UDP
	// https://github.com/enfein/mieru/blob/main/docs/client-install.md#simple-sharing-link
	result := T.Outbound{
		Type: C.TypeMieru,
		Tag:  u.Name,
		Options: &T.MieruOutboundOptions{
			DialerOptions:    getDialerOptions(decoded),
			ServerOptions:    u.GetServerOption(),
			UserName:         u.Username,
			Password:         u.Password,
			Transport:        strings.Split(getOneOfN(decoded, "", "protocol"), ","),
			Multiplexing:     getOneOfN(decoded, "", "multiplexing"),
			ServerPortRanges: strings.Split(getOneOfN(decoded, "", "port"), ","),
		},
	}

	return &result, nil
}
