package ray2sing_test

import (
	"strings"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// Some subscriptions (openproxylist) write the links HTML-escaped, with "&amp;" between the
// parameters. They must convert as the same link with "&".
func TestHTMLEscapedAmpersand(t *testing.T) {
	links := []string{
		"vless://2446e2e2-1ce3-4502-9050-1dd32bacc68c@192.0.2.10:25021?security=reality&encryption=none&pbk=-hFM70jDWMhgt8_LMngMf6sremkKDA4GmjrR-xpt3B0&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=www.example.com&sid=17fa3af0924c88b3#🇪🇪 vless-EE",
		"trojan://secret@192.0.2.11:443?security=tls&sni=trojan.example.com&type=ws&host=trojan.example.com&path=%2Fws#A & B",
	}
	for _, plain := range links {
		escaped := strings.ReplaceAll(plain, "&", "&amp;")
		want, err := ray2sing.Ray2Singbox(libbox.BaseContext(nil), plain, false)
		if err != nil {
			t.Fatalf("plain link: %v", err)
		}
		got, err := ray2sing.Ray2Singbox(libbox.BaseContext(nil), escaped, false)
		if err != nil {
			t.Fatalf("escaped link: %v", err)
		}
		if string(got) != string(want) {
			t.Errorf("escaped link converts differently:\n%s\nwant\n%s", got, want)
		}
	}
	got, err := ray2sing.Ray2Singbox(libbox.BaseContext(nil), strings.ReplaceAll(links[0], "&", "&amp;"), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"public_key":"-hFM70jDWMhgt8_LMngMf6sremkKDA4GmjrR-xpt3B0"`, `"short_id":"17fa3af0924c88b3"`, `"flow":"xtls-rprx-vision"`} {
		if !strings.Contains(string(got), field) {
			t.Errorf("missing %s in\n%s", field, got)
		}
	}
}

// A trojan link without "security" is TLS, as in Xray and v2rayN; "security=none" is not.
func TestTrojanTLSByDefault(t *testing.T) {
	for link, want := range map[string]string{
		"trojan://secret@192.0.2.11:443?sni=trojan.example.com#a":                                 `"tls":{"enabled":true,"server_name":"trojan.example.com"}`,
		"trojan://secret@192.0.2.11:8446?allowInsecure=1&type=grpc&serviceName=grpc-video-call#b": `"tls":{"enabled":true,"insecure":true,`,
		"trojan://secret@192.0.2.11:80?security=none&type=ws#c":                                   "",
	} {
		got, err := ray2sing.Ray2Singbox(libbox.BaseContext(nil), link, false)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		if want == "" && strings.Contains(string(got), `"tls"`) || want != "" && !strings.Contains(string(got), want) {
			t.Errorf("%s: want %s in\n%s", link, want, got)
		}
	}
}
