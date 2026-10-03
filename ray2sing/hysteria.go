package ray2sing

import (
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

func HysteriaSingbox(hysteriaURL string) (*T.Outbound, error) {
	u, err := ParseUrl(hysteriaURL, 443)
	if err != nil {
		return nil, err
	}
	SNI := getOneOfN(u.Params, "", "peer", "sni")
	opts := T.HysteriaOutboundOptions{
		ServerOptions: u.GetServerOption(),
		ServerPorts:   u.PortRanges,
		OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
			TLS: &T.OutboundTLSOptions{
				Enabled:    true,
				DisableSNI: isIPOnly(SNI),
				ServerName: SNI,
				Insecure:   u.Params["insecure"] == "1",
			},
		},
	}
	if alpn := u.Params["alpn"]; alpn != "" {
		opts.TLS.ALPN = strings.Split(alpn, ",")
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

	opts.Obfs = getOneOfN(u.Params, "", "obfsparam", "obfspassword")
	// hiddifypanel puts the obfs password directly in "obfs" ("xplus" is only the obfs mode name)
	if obfs := u.Params["obfs"]; opts.Obfs == "" && obfs != "" && obfs != "xplus" {
		opts.Obfs = obfs
	}
	// opts.TurnRelay, err = u.GetRelayOptions()
	if err != nil {
		return nil, err
	}
	return singOut, nil
}
