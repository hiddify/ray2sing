package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestTrojan(t *testing.T) {

	url := "trojan://your_password@aws-ar-buenosaires-1.f1cflineb.com:443?host=aws-ar-buenosaires-1.f1cflineb.com&path=%2Ff1rocket&security=tls&sni=aws-ar-buenosaires-1.f1cflineb.com&type=ws#رایگان | TROJAN | @VmessProtocol | RELAY🚩 | 0️⃣1️⃣"

	// Define the expected JSON structure
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "trojan",
			"tag": "رایگان | TROJAN | @VmessProtocol | RELAY🚩 | 0️⃣1️⃣ § 0",
			"server": "aws-ar-buenosaires-1.f1cflineb.com",
			"server_port": 443,
			"password": "your_password",
			"tls": {
			  "enabled": true,
			  "server_name": "aws-ar-buenosaires-1.f1cflineb.com",
			  "alpn": "http/1.1"
			},
			"transport": {
			  "type": "ws",
			  "path": "/f1rocket",
			  "headers": {
				"Host": "aws-ar-buenosaires-1.f1cflineb.com"
			  },
			  "early_data_header_name": "Sec-WebSocket-Protocol"
			}
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
