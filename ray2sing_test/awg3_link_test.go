package ray2sing_test

import (
	"strings"
	"testing"
)

// An AmneziaWG 3.x wg:// link: snake_case keys, base64 keys with an unescaped "+", a base64
// header_protection_key, and the 3.x ranges and flags.
func TestWgLinkAwg3(t *testing.T) {
	pub := "EdvQI284oYKlm6YqUXn4gd6wWqZC+HAsJQCmm9+GdRQ%3D"
	hpk := "XG1+gpKcCUzj/03OKxoXBusfUwCcZs5V/v20pJIsvPs%3D"
	got := convert(t, "wg://198.51.100.1:51820?private_key="+strings.ReplaceAll(testPrivateKey, "=", "%3D")+
		"&local_address=10.8.1.2/32&mtu=1280&enable_amnezia=true&jc=4&jmin=78&jmax=292&s1=87&s2=146&s3=15&s4=17"+
		"&h1=13018123&h2=922202939&h3=1214307164&h4=1988128689&i1=%3Cr%20240%3E&header_protection_key="+hpk+
		"&content_padding_addition=9-33&rekey_after_time=112-151&rekey_timeout=6-10&reject_after_time=200-285"+
		"&keepalive_timeout=12-15&max_handshake_attempts=19-26&random_trailers=true&disable_cookies=true"+
		"&public_key="+pub+"&persistent_keepalive_interval=25#%F0%9F%87%B5%F0%9F%87%B1%20Amnezia")
	wantAll(t, got, `"type":"awg"`, `"address":"10.8.1.2/32"`, `"mtu":1280`,
		`"public_key":"EdvQI284oYKlm6YqUXn4gd6wWqZC+HAsJQCmm9+GdRQ="`,
		`"persistent_keepalive_interval":25`,
		`"jc":4`, `"s4":17`, `"h4":"1988128689"`, `"i1":"<r 240>"`,
		`"header_protection_key":"5c6d7e82929c094ce3ff4dce2b1a1706eb1f53009c66ce55fefdb4a4922cbcfb"`,
		`"content_padding_addition":"9-33"`, `"rekey_after_time":"112-151"`, `"rekey_timeout":"6-10"`,
		`"reject_after_time":"200-285"`, `"keepalive_timeout":"12-15"`, `"max_handshake_attempts":"19-26"`,
		`"random_trailers":true`, `"disable_cookies":true`)
}

// The same AmneziaWG 3.x values in a .conf.
func TestAwgConf3(t *testing.T) {
	got := convert(t, `[Interface]
PrivateKey = `+testPrivateKey+`
Address = 10.8.1.2/32
S1 = 87
S2 = 146
HeaderProtectionKey = XG1+gpKcCUzj/03OKxoXBusfUwCcZs5V/v20pJIsvPs=
ContentPaddingAddition = 9-33
RandomTrailers = true

[Peer]
PublicKey = `+testPublicKey+`
Endpoint = 198.51.100.1:51820
`)
	wantAll(t, got, `"type":"awg"`,
		`"header_protection_key":"5c6d7e82929c094ce3ff4dce2b1a1706eb1f53009c66ce55fefdb4a4922cbcfb"`,
		`"content_padding_addition":"9-33"`, `"random_trailers":true`)
}
