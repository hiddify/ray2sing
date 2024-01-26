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


func TestShadowsocksEIHBase64(t *testing.T) {
	// EIH extension: https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
	// Named as "multi-user" in https://sing-box.sagernet.org/configuration/inbound/shadowsocks/#structure

	url := "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206cTdENzRBVjhCRlY0UUk3NWVqVS9nTXViWER4ejEyRysvU2o3RUlyTHZCdz06L21JTjIvb0pZRzBJbHZGYlA1UEs5VmhGcnlTODl0ZjFEK3E4SUR1czA0VT0%3D@10.20.30.40:54321#sample-tag"
	// b64decode(MjAyMi1...) = "2022-blake3-aes-128-gcm:q7D74AV8BFV4QI75ejU/gMubXDxz12G+/Sj7EIrLvBw=:/mIN2/oJYG0IlvFbP5PK9VhFryS89tf1D+q8IDus04U="

	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "shadowsocks",
			"tag": "sample-tag § 0",
			"server": "10.20.30.40",
			"server_port": 54321,
			"method": "2022-blake3-aes-128-gcm",
			"password": "q7D74AV8BFV4QI75ejU/gMubXDxz12G+/Sj7EIrLvBw=:/mIN2/oJYG0IlvFbP5PK9VhFryS89tf1D+q8IDus04U="
		  }
		]
	  }
	`

	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}


func TestShadowsocksEIHPlain(t *testing.T) {
	// EIH extension: https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
	// Named as "multi-user" in https://sing-box.sagernet.org/configuration/inbound/shadowsocks/#structure

	url := "ss://2022-blake3-aes-128-gcm:q7D74AV8BFV4QI75ejU%2FgMubXDxz12G%2B%2FSj7EIrLvBw%3D:%2FmIN2%2FoJYG0IlvFbP5PK9VhFryS89tf1D%2Bq8IDus04U%3D@10.20.30.40:54321#sample-tag"

	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "shadowsocks",
			"tag": "sample-tag § 0",
			"server": "10.20.30.40",
			"server_port": 54321,
			"method": "2022-blake3-aes-128-gcm",
			"password": "q7D74AV8BFV4QI75ejU/gMubXDxz12G+/Sj7EIrLvBw=:/mIN2/oJYG0IlvFbP5PK9VhFryS89tf1D+q8IDus04U="
		  }
		]
	  }
	`

	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
