package ray2sing_test

import (
	"net/http"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestBeePass(t *testing.T) {
	if resp, err := http.Get("https://s3.amazonaws.com/beedynconprd/ng4lf90ip01zstlyle4r0t56x1qli4cvmt2ws6nh0kdz1jpgzyedogxt3mpxfbxi.json"); err != nil || resp.StatusCode != http.StatusOK {
		t.Skip("remote BeePass ssconf endpoint is unavailable")
	} else {
		resp.Body.Close()
	}
	url := "ssconf://s3.amazonaws.com/beedynconprd/ng4lf90ip01zstlyle4r0t56x1qli4cvmt2ws6nh0kdz1jpgzyedogxt3mpxfbxi.json#BeePass"

	// Define the expected JSON structure
	expectedJSON := `{
		"outbounds": [
			{
				"type": "shadowsocks",
				"tag": "BeePass § 0",
				"server": "beacomf.xyz",
				"server_port": 8080,
				"method": "chacha20-ietf-poly1305",
				"password": "nfzmfcBTcsj287NxNgMZDu"
			}
		]
	}`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
