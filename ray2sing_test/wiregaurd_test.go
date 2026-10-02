package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestWiregaurd(t *testing.T) {

	url := "wg://1.2.3.4:222/?pk=cGsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&local_address=10.0.0.2/24&peer_public_key=cHViAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&pre_shared_key=cHNrAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&mtu=1380&reserved=0,0,0"

	// Define the expected JSON structure
	expectedJSON := `
	{
		"endpoints": [
		  {
			"type": "wireguard",
			"tag": "WG § 0",
			"mtu": 1380,
			"address": "10.0.0.2/24",
			"private_key": "cGsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"peers": [
			  {
				"address": "1.2.3.4",
				"port": 222,
				"public_key": "cHViAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"pre_shared_key": "cHNrAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"allowed_ips": ["0.0.0.0/0", "::/0"],
				"reserved": "AAAA"
			  }
			]
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}

func TestAmneziaWG(t *testing.T) {

	url := "awg://1.2.3.4:51820/?pk=cGsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&address=10.8.0.2/32&publickey=cHViAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&mtu=1280&jc=4&jmin=40&jmax=70&s1=0&s2=0&h1=1&h2=2&h3=3&h4=4#awg"

	expectedJSON := `
	{
		"endpoints": [
		  {
			"type": "awg",
			"tag": "awg § 0",
			"useIntegratedTun": false,
			"mtu": 1280,
			"address": "10.8.0.2/32",
			"private_key": "cGsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"awg": {"jc": 4, "jmin": 40, "jmax": 70, "h1": "1", "h2": "2", "h3": "3", "h4": "4"},
			"peers": [
			  {
				"address": "1.2.3.4",
				"port": 51820,
				"public_key": "cHViAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"allowed_ips": ["0.0.0.0/0", "::/0"]
			  }
			]
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
