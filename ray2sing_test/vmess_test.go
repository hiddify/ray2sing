package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestVmess(t *testing.T) {

	url := "vmess://eyJhZGQiOiI1MS4xNjEuMTMwLjE3MyIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiJkNDNlZTVlMy0xYjA3LTU2ZDctYjJlYS04ZDIyYzQ0ZmRjNjYiLCJuZXQiOiJ0Y3AiLCJwYXRoIjoiIiwicG9ydCI6IjgwODAiLCJzY3kiOiJjaGFjaGEyMC1wb2x5MTMwNSIsInNuaSI6IiIsInRscyI6IiIsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Ilx1MDYzMVx1MDYyN1x1MDZjY1x1MDZhZlx1MDYyN1x1MDY0NiB8IFZNRVNTIHwgQFdhdGFzaGlfVlBOIHwgQVVcdWQ4M2NcdWRkZTZcdWQ4M2NcdWRkZmEgfCAwXHVmZTBmXHUyMGUzMVx1ZmUwZlx1MjBlMyJ9"

	// Define the expected JSON structure
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "vmess",
			"tag": "رایگان | VMESS | @Watashi_VPN | AU🇦🇺 | 0️⃣1️⃣ § 0",
			"server": "51.161.130.173",
			"server_port": 8080,
			"uuid": "d43ee5e3-1b07-56d7-b2ea-8d22c44fdc66",
			"security": "chacha20-poly1305",
			"authenticated_length": true,
			"packet_encoding": "xudp"
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
