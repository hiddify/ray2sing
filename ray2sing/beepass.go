package ray2sing

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

type beepassData struct {
	Server     string `json:"server"`
	ServerPort string `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Prefix     string `json:"prefix"`
	Name       string `json:"name"`
}

func fetchSSConf(parsedURL *url.URL) ([]byte, error) {

	// Construct the HTTP URL
	httpURL := "https://" + parsedURL.Host + parsedURL.Path

	// Make the HTTP request
	resp, err := http.Get(httpURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
func parseAndFetchBeePass(body []byte) (*beepassData, error) {

	// Decode JSON
	var config beepassData
	err := json.Unmarshal(body, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func BeepassSingbox(beepassUrl string) (*T.Outbound, error) {
	parsedURL, err := url.Parse(beepassUrl)
	if err != nil {
		return nil, err
	}
	body, err := fetchSSConf(parsedURL)
	if err != nil {
		return nil, err
	}
	decoded, err := parseAndFetchBeePass(body)
	if err != nil {
		return ShadowsocksSingbox(strings.TrimSpace(string(body)))
		// return nil, err
	}
	if decoded.Name == "" {
		decoded.Name = parsedURL.Fragment
	}
	result := T.Outbound{
		Type: "shadowsocks",
		Tag:  decoded.Name,
		Options: T.ShadowsocksOutboundOptions{
			ServerOptions: T.ServerOptions{
				Server:     decoded.Server,
				ServerPort: toUInt16(decoded.ServerPort, 443),
			},
			Method:   decoded.Method,
			Password: decoded.Password,
		},
	}

	return &result, nil
}
