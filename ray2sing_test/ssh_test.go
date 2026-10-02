package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestBase(t *testing.T) {

	url := "ssh://user:pass@server:22/?pk=pk&hk=hk"

	// Define the expected JSON structure
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "ssh",
			"tag": "ssh § 0",
			"server": "server",
			"server_port": 22,
			"user": "user",
			"password": "pass",
			"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\npk\n-----END OPENSSH PRIVATE KEY-----\n",
			"host_key": "hk",
			"udp_over_tcp": true
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
