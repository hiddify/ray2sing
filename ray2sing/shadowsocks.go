package ray2sing

import (
	T "github.com/sagernet/sing-box/option"

	"net/url"
	"strings"
)

func parseShadowsocks(configStr string) (map[string]string, error) {
	parsedURL, _ := url.Parse(configStr)
	var encryption_method string
	var password string

	userInfo, err := decodeBase64IfNeeded(parsedURL.User.String())
	if err != nil {
		// If there's an error in decoding, use the original string
		encryption_method = parsedURL.User.Username()
		password, _ = parsedURL.User.Password()

	} else {
		// If decoding is successful, use the decoded string
		userDetails := strings.SplitN(userInfo, ":", 2)
		encryption_method = userDetails[0]
		password = userDetails[1]
	}
	if password == "" {
		password = encryption_method
		encryption_method = "none"
	}

	server := map[string]string{
		"encryption_method": encryption_method,
		"password":          password,
		"server":            parsedURL.Hostname(),
		"port":              parsedURL.Port(),
		"name":              parsedURL.Fragment,
	}
	// fmt.Printf("MMMM %v", server)
	return server, nil
}

func ShadowsocksSingbox(shadowsocksUrl string) (*T.Outbound, error) {
	u, err := ParseUrl(shadowsocksUrl, 443)
	if err != nil {
		return nil, err
	}

	decoded := u.Params
	defaultMethod := "chacha20-ietf-poly1305"
	if u.Password == "" {
		u.Password = u.Username
		u.Username = "none"
	}
	if u.Username != "" {
		defaultMethod = u.Username
	}

	result := T.Outbound{
		Type: "shadowsocks",
		Tag:  u.Name,
		Options: &T.ShadowsocksOutboundOptions{
			ServerOptions: u.GetServerOption(),
			Method:        defaultMethod,
			Password:      u.Password,
			Plugin:        decoded["plugin"],
			PluginOptions: decoded["pluginopts"],
		},
	}

	return &result, nil
}
