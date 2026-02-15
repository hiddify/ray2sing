package ray2sing

import (
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func MieruSingbox(uri string) (*T.Outbound, error) {
	u, err := ParseUrl(uri, 0)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// mierus://baozi:manlianpenfen@1.2.3.4?handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_HIGH&port=6666&port=9998-9999&port=6489&port=4896&profile=default&protocol=TCP&protocol=TCP&protocol=UDP&protocol=UDP
	// https://github.com/enfein/mieru/blob/main/docs/client-install.md#simple-sharing-link
	protocols := strings.Split(getOneOfN(decoded, "", "protocol"), ",")
	ports := strings.Split(getOneOfN(decoded, "", "port"), ",")
	if len(protocols) == len(ports)+1 {
		ports = append([]string{fmt.Sprintf("%d", u.Port)}, ports...)
	}
	if len(protocols) != len(ports) {
		return nil, E.New("the number of protocols must be the same as the number of ports")
	}
	transports := make([]option.MieruPortBinding, len(protocols))
	for i := 0; i < len(protocols); i++ {
		transports[i] = option.MieruPortBinding{
			Protocol: protocols[i],
		}
		if strings.Contains(ports[i], "-") {
			transports[i].PortRange = ports[i]
		} else {
			transports[i].Port = toUInt16(ports[i], 0)
		}
	}
	result := T.Outbound{
		Type: C.TypeMieru,
		Tag:  u.Name,
		Options: &T.MieruOutboundOptions{
			DialerOptions: getDialerOptions(decoded),
			ServerOptions: T.ServerOptions{
				Server: u.Hostname,
			},
			UserName:      u.Username,
			Password:      u.Password,
			PortBindings:  transports,
			Multiplexing:  getOneOfN(decoded, "", "multiplexing"),
			HandshakeMode: getOneOfN(decoded, "", "handshakemode"),
		},
	}

	return &result, nil
}
