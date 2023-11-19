package ray2sing

import (
	"strconv"

	T "github.com/sagernet/sing-box/option"
)

func HysteriaSingbox(hysteriaURL string) (*T.Outbound, error) {
	u, err := ParseUrl(hysteriaURL)
	if err != nil {
		return nil, err
	}
	SNI := u.Params["peer"]
	singOut := &T.Outbound{
		Type: u.Scheme,
		Tag:  u.Name,
		HysteriaOptions: T.HysteriaOutboundOptions{
			ServerOptions: u.GetServerOption(),
			TLS: &T.OutboundTLSOptions{
				Enabled:    true,
				DisableSNI: isIPOnly(SNI),
				ServerName: SNI,
				Insecure:   u.Params["insecure"] == "1",
			},
		},
	}
	options := singOut.HysteriaOptions

	options.AuthString = u.Params["auth"]

	upMbps, err := strconv.Atoi(u.Params["upmbps"])
	if err == nil {
		options.UpMbps = upMbps
	}

	downMbps, err := strconv.Atoi(u.Params["downmbps"])
	if err == nil {
		options.DownMbps = downMbps
	}

	options.Obfs = u.Params["obfsParam"]
	options.TurnRelay, err = u.GetRelayOptions()
	if err != nil {
		return nil, err
	}
	return singOut, nil
}
