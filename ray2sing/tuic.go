package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"time"
)

func TuicSingbox(tuicUrl string) (*T.Outbound, error) {
	u, err := ParseUrl(tuicUrl, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	valECH, hasECH := decoded["ech"]
	hasECH = hasECH && (valECH != "0")
	var ECHOpts *T.OutboundECHOptions
	ECHOpts = nil
	if hasECH {
		ECHOpts = &T.OutboundECHOptions{
			Enabled: hasECH,
		}
	}
	// turnRelay, err := ParseTurnURL(decoded["relay"])
	// if err != nil {
	// 	return nil, err
	// }
	result := T.Outbound{
		Type: "tuic",
		Tag:  u.Name,
		Options: T.TUICOutboundOptions{
			ServerOptions:     u.GetServerOption(),
			UUID:              u.Username,
			Password:          u.Password,
			CongestionControl: decoded["congestioncontrol"],
			UDPRelayMode:      decoded["udprelaymode"],
			ZeroRTTHandshake:  false,
			Heartbeat:         badoption.Duration(10 * time.Second),
			OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
				TLS: &T.OutboundTLSOptions{
					Enabled:    true,
					DisableSNI: decoded["sni"] == "",
					ServerName: decoded["sni"],
					Insecure:   decoded["allowinsecure"] == "1" || decoded["insecure"] == "1",
					ALPN:       []string{"h3", "spdy/3.1"},
					ECH:        ECHOpts,
				},
			},
			// TurnRelay: turnRelay,
		},
	}

	return &result, nil
}
