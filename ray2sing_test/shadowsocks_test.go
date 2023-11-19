package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestShadowsocks(t *testing.T) {

	url := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0T3dPeXZsWGlZNUFUSkFVT3BYTlBO@5.35.34.107:55990#%D8%B1%D8%A7%DB%8C%DA%AF%D8%A7%D9%86+%7C+SS+%7C+%40iP_CF+%7C+RU%F0%9F%87%B7%F0%9F%87%BA+%7C+0%EF%B8%8F%E2%83%A31%EF%B8%8F%E2%83%A3"

	// Define the expected JSON structure
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "shadowsocks",
			"tag": "رایگان+|+SS+|+@iP_CF+|+RU🇷🇺+|+0️⃣1️⃣ § 0",
			"server": "5.35.34.107",
			"server_port": 55990,
			"method": "chacha20-ietf-poly1305",
			"password": "tOwOyvlXiY5ATJAUOpXNPN"
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
