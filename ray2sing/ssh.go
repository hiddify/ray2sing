package ray2sing

import (
	T "github.com/sagernet/sing-box/option"

	"strings"
)

func SSHSingbox(sshURL string) (*T.Outbound, error) {
	u, err := ParseUrl(sshURL, 22)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	prefix := "-----BEGIN OPENSSH PRIVATE KEY-----"
	suffix := "-----END OPENSSH PRIVATE KEY-----"

	privkeys := strings.Split(decoded["pk"], ",")
	if len(privkeys) == 1 && privkeys[0] == "" {
		privkeys = []string{}
	}
	for i := 0; i < len(privkeys); i++ {
		body := strings.ReplaceAll(privkeys[i], prefix, "")
		body = strings.ReplaceAll(body, suffix, "")
		body = strings.TrimSpace(body)
		privkeys[i] = prefix + "\n" + body + "\n" + suffix + "\n"
	}

	hostkeys := strings.Split(decoded["hk"], ",")

	result := T.Outbound{
		Type: "ssh",
		Tag:  u.Name,
		Options: &T.SSHOutboundOptions{
			ServerOptions: u.GetServerOption(),
			User:          u.Username,
			Password:      u.Password,
			PrivateKey:    privkeys,
			HostKey:       hostkeys,
			UDPOverTCP: &T.UDPOverTCPOptions{
				Enabled: true,
			},
		},
	}
	return &result, nil
}
