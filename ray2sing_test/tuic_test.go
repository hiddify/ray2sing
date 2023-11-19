package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestTuic(t *testing.T) {

	url := "tuic://3618921b-adeb-4bd3-a2a0-f98b72a674b1:dongtaiwang@108.181.24.7:23450?allow_insecure=1&alpn=h3&congestion_control=bbr&sni=www.google.com&udp_relay_mode=native#رایگان | TUIC | @V2rayCollector | CA🇨🇦 | 0️⃣1️⃣"

	// Define the expected JSON structure
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "tuic",
			"tag": "رایگان | TUIC | @V2rayCollector | CA🇨🇦 | 0️⃣1️⃣ § 0",
			"server": "108.181.24.7",
			"server_port": 23450,
			"uuid": "3618921b-adeb-4bd3-a2a0-f98b72a674b1",
			"password": "dongtaiwang",
			"congestion_control": "bbr",
			"udp_relay_mode": "native",
			"heartbeat": "10s",
			"tls": {
			  "enabled": true,
			  "server_name": "www.google.com",
			  "insecure": true,
			  "alpn": [
				"h3",
				"spdy/3.1"
			  ]
			}
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
