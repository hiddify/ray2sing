package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

// TorSingbox reads a tor:// link, the embedded Tor client with its defaults, as an aether://
// link with tor= names it: tor://#name.
func TorSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	return &T.Outbound{Type: C.TypeTor, Tag: u.Name, Options: &T.TorOutboundOptions{}}, nil
}
