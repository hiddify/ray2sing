package ray2sing

import (
	"net/url"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// HysteriaURLData holds the parsed data from a Hysteria URL.
type UrlSchema struct {
	Scheme   string
	Username string
	Password string
	Hostname string
	Port     uint16
	Name     string
	Params   map[string]string
}

func (u UrlSchema) GetServerOption() T.ServerOptions {
	return T.ServerOptions{
		Server:     u.Hostname,
		ServerPort: u.Port,
	}
}

// func (u UrlSchema) GetRelayOptions() (*T.TurnRelayOptions, error) {
// 	return ParseTurnURL(u.Params["relay"])
// }

// parseHysteria2 parses a given URL and returns a HysteriaURLData struct.
func ParseUrl(inputURL string, defaultPort uint16) (*UrlSchema, error) {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return nil, err
	}
	port := toUInt16(parsedURL.Port(), defaultPort)

	data := &UrlSchema{
		Scheme:   parsedURL.Scheme,
		Username: parsedURL.User.Username(),
		Password: getPassword(parsedURL),
		Hostname: parsedURL.Hostname(),
		Port:     port,
		Name:     parsedURL.Fragment,
		Params:   make(map[string]string),
	}
	userInfo, err := decodeBase64IfNeeded(data.Username)
	// fmt.Print(userInfo)
	if err == nil {
		// If decoding is successful, use the decoded string
		userDetails := strings.SplitN(userInfo, ":", 2)
		if len(userDetails) > 1 {
			data.Username = userDetails[0]
			data.Password = userDetails[1]
		}
	}

	for key, values := range parsedURL.Query() {
		data.Params[strings.ReplaceAll(strings.ToLower(key), "_", "")] = strings.Join(values, ",")
	}

	return data, nil
}

func getPassword(u *url.URL) string {
	if password, ok := u.User.Password(); ok {
		return password
	}
	return ""
}
