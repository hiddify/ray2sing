package ray2sing

import (
	"encoding/json"
	"net/http"
	"net/url"

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

func parseAndFetchBeePass(customURL string) (*beepassData, error) {
	// Parse the custom URL
	parsedURL, err := url.Parse(customURL)
	if err != nil {
		return nil, err
	}

	// Construct the HTTP URL
	httpURL := "https://" + parsedURL.Host + parsedURL.Path

	// Make the HTTP request
	resp, err := http.Get(httpURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Decode JSON
	var config beepassData
	err = json.NewDecoder(resp.Body).Decode(&config)
	if err != nil {
		return nil, err
	}
	if config.Name == "" {
		config.Name = parsedURL.Fragment
	}

	return &config, nil
}

func BeepassSingbox(beepassUrl string) (*T.Outbound, error) {
	decoded, err := parseAndFetchBeePass(beepassUrl)
	if err != nil {
		return nil, err
	}

	result := T.Outbound{
		Type: "shadowsocks",
		Tag:  decoded.Name,
		ShadowsocksOptions: T.ShadowsocksOutboundOptions{
			ServerOptions: T.ServerOptions{
				Server:     decoded.Server,
				ServerPort: toInt16(decoded.ServerPort, 443),
			},
			Method:   decoded.Method,
			Password: decoded.Password,
		},
	}

	return &result, nil
}
