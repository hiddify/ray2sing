package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestSnellUserKeyFromUsername(t *testing.T) {
	url := "snell://user-uuid@1.2.3.4:19708?psk=shared-psk&version=6&mode=default#Snell"
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "snell",
			"tag": "Snell § 0",
			"version": 6,
			"server": "1.2.3.4",
			"server_port": 19708,
			"psk": "shared-psk",
			"userkey": "user-uuid",
			"mode": "default"
		  }
		]
	}
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}

func TestSnellLegacyPSKUsername(t *testing.T) {
	url := "snell://only-psk@1.2.3.4:1?version=4#s"
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "snell",
			"tag": "s § 0",
			"version": 4,
			"server": "1.2.3.4",
			"server_port": 1,
			"psk": "only-psk"
		  }
		]
	}
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
