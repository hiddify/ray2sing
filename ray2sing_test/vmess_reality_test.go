package ray2sing_test

import (
	"encoding/base64"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestVmessRealityTLS(t *testing.T) {
	vmess := `{"v":"2","ps":"vmess-reality","add":"1.2.3.4","port":"443","id":"9a474e04-39c3-4517-8787-32c54691d76b","aid":"0","scy":"auto","net":"xhttp","type":"auto","host":"chess.com","path":"/p","tls":"reality","sni":"chess.com","fp":"chrome","pbk":"yanlaRXp_Qaive33liPQzYJbIsh5rFZmJ8Bd-Iy_wjM","sid":"1bf7","alpn":"h2,http/1.1"}`
	url := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmess))
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "vmess",
			"tag": "vmess-reality § 0",
			"server": "1.2.3.4",
			"server_port": 443,
			"uuid": "9a474e04-39c3-4517-8787-32c54691d76b",
			"security": "auto",
			"authenticated_length": true,
			"tls": {
			  "enabled": true,
			  "server_name": "chess.com",
			  "alpn": ["h2", "http/1.1"],
			  "utls": {
				"enabled": true,
				"fingerprint": "chrome"
			  },
			  "reality": {
				"enabled": true,
				"public_key": "yanlaRXp_Qaive33liPQzYJbIsh5rFZmJ8Bd-Iy_wjM",
				"short_id": "1bf7"
			  }
			},
			"packet_encoding": "xudp",
			"transport": {
			  "type": "xhttp",
			  "host": "chess.com",
			  "path": "/p",
			  "mode": "auto"
			}
		  }
		]
	}
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
