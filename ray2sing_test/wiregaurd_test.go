package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestWiregaurd(t *testing.T) {

	url := "wg://[server]:222/?pk=[private_key]&local_address=10.0.0.2/24&peer_pk=[peer_public_key]&pre_shared_key=[pre_shared_key]&workers=[workers]&mtu=[mtu]&reserved=0,0,0"

	// Define the expected JSON structure
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "wireguard",
			"tag": " § 0",
			"local_address": "10.0.0.2/24",
			"private_key": "[private_key]",
			"server": "server",
			"server_port": 222,
			"peer_public_key": "[peer_public_key]",
			"pre_shared_key": "[pre_shared_key]",
			"reserved": "AAAA"
		  }
		]
	  }	
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
