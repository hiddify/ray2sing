package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

// tfo=1 turns TCP Fast Open on for the link; without it the dialer leaves it off.
func TestTFOParameter(t *testing.T) {
	url := "snell://user-uuid@1.2.3.4:19708?psk=shared-psk&version=6&mode=default&tfo=1#Snell"
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "snell",
			"tag": "Snell § 0",
			"version": 6,
			"tcp_fast_open": true,
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

// A fragment needs TCP Fast Open off, so it wins over tfo=1.
func TestTFOParameterOffWithFragment(t *testing.T) {
	url := "snell://user-uuid@1.2.3.4:19708?psk=shared-psk&version=6&mode=default&tfo=1&fragment=10-100,50-200,tlshello#Snell"
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "snell",
			"tag": "Snell § 0",
			"version": 6,
			"tls_fragment": {
			  "enabled": true,
			  "size": "10-100",
			  "sleep": "50-200"
			},
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
