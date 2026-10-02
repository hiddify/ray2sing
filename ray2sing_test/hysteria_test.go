package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestHysteria(t *testing.T) {

	url := "hysteria://host:443?protocol=udp&auth=123456&peer=sni.domain&insecure=1&upmbps=100&downmbps=100&alpn=hysteria&obfs=xplus&obfsParam=123456#remarks"

	// Define the expected JSON structure
	expectedJSON := `{
		"outbounds": [
			{
				"type": "hysteria",
				"tag": "remarks § 0",
				"server": "host",
				"server_port": 443,
				"up_mbps": 100,
				"down_mbps": 100,
				"obfs": "123456",
				"auth_str": "123456",
				"tls": {
				"enabled": true,
				"server_name": "sni.domain",
				"insecure": true,
				"alpn": "hysteria"
				}
			}
		]
	}`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
