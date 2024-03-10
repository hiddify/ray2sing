package ray2sing

import (
	"strconv"

	T "github.com/sagernet/sing-box/option"
)

func HysteriaSingbox(hysteriaURL string) (*T.Outbound, error) {
	u, err := ParseUrl(hysteriaURL, 443)
	if err != nil {
		return nil, err
	}
	SNI := u.Params["peer"]
	singOut := &T.Outbound{
		Type: u.Scheme,
		Tag:  u.Name,
		HysteriaOptions: T.HysteriaOutboundOptions{
			ServerOptions: u.GetServerOption(),
			OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
				TLS: &T.OutboundTLSOptions{
					Enabled:    true,
					DisableSNI: isIPOnly(SNI),
					ServerName: SNI,
					Insecure:   u.Params["insecure"] == "1",
				},
			},
		},
	}

	singOut.HysteriaOptions.AuthString = u.Params["auth"]

	upMbps, err := strconv.Atoi(u.Params["upmbps"])
	if err == nil {
		singOut.HysteriaOptions.UpMbps = upMbps
	}

	downMbps, err := strconv.Atoi(u.Params["downmbps"])
	if err == nil {
		singOut.HysteriaOptions.DownMbps = downMbps
	}

	singOut.HysteriaOptions.Obfs = u.Params["obfsParam"]
	singOut.HysteriaOptions.TurnRelay, err = u.GetRelayOptions()
	if err != nil {
		return nil, err
	}
	return singOut, nil
}
