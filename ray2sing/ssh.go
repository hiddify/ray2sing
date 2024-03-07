package ray2sing

import (
	T "github.com/sagernet/sing-box/option"

	"encoding/base64"
	"strings"
)

func SSHSingbox(sshURL string) (*T.Outbound, error) {
	u, err := ParseUrl(sshURL, 22)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	prefix := "-----BEGIN OPENSSH PRIVATE KEY-----\n"
	suffix := "\n-----END OPENSSH PRIVATE KEY-----\n"
	decodedPkBytes, err := base64.StdEncoding.DecodeString(decoded["pk"])
	if err != nil {
		return nil, err
	}
	privkeys := strings.Split(string(decodedPkBytes), ",")
	if len(privkeys) == 1 && privkeys[0] == "" {
		privkeys = []string{}
	}
	for i := 0; i < len(privkeys); i++ {
		privkeys[i] = prefix + privkeys[i] + suffix
	}
	decodedHkBytes, err := base64.StdEncoding.DecodeString(decoded["hk"])
	if err != nil {
		return nil, err
	}
	hostkeys := strings.Split(string(decodedHkBytes), ",")

	result := T.Outbound{
		Type: "ssh",
		Tag:  u.Name,
		SSHOptions: T.SSHOutboundOptions{
			ServerOptions: u.GetServerOption(),
			User:          u.Username,
			Password:      u.Password,
			PrivateKey:    privkeys,
			HostKey:       hostkeys,
		},
	}
	return &result, nil
}
