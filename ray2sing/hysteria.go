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
	opts := T.HysteriaOutboundOptions{
		ServerOptions: u.GetServerOption(),
		OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
			TLS: &T.OutboundTLSOptions{
				Enabled:    true,
				DisableSNI: isIPOnly(SNI),
				ServerName: SNI,
				Insecure:   u.Params["insecure"] == "1",
			},
		},
	}
	singOut := &T.Outbound{
		Type:    u.Scheme,
		Tag:     u.Name,
		Options: &opts,
	}

	opts.AuthString = u.Params["auth"]

	upMbps, err := strconv.Atoi(u.Params["upmbps"])
	if err == nil {
		opts.UpMbps = upMbps
	}

	downMbps, err := strconv.Atoi(u.Params["downmbps"])
	if err == nil {
		opts.DownMbps = downMbps
	}

	opts.Obfs = u.Params["obfsParam"]
	// opts.TurnRelay, err = u.GetRelayOptions()
	if err != nil {
		return nil, err
	}
	return singOut, nil
}
