package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestHysteria2(t *testing.T) {

	url := "hysteria2://letmein@example.com/?insecure=1&obfs=salamander&obfs-password=gawrgura&pinSHA256=deadbeef&sni=real.example.com"

	// Define the expected JSON structure
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "hysteria2",
			"tag": " § 0",
			"server": "example.com",
			"server_port": 443,
			"obfs": {
			  "type": "salamander",
			  "password": "gawrgura"
			},
			"password": "letmein",
			"tls": {
			  "enabled": true,
			  "server_name": "real.example.com",
			  "insecure": true
			}
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
