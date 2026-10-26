package ray2sing_test

import (
	"strings"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
)

func TestXHTTPQuicOmitsUTLS(t *testing.T) {
	url := "vless://9a474e04-39c3-4517-8787-32c54691d76b@example.com:443/?fp=chrome&sni=example.com&security=tls&alpn=h3&type=xhttp&mode=auto&path=%2Fp&host=example.com&encryption=none#quic"
	out, err := ray2sing.Ray2Singbox(libbox.BaseContext(nil), url, false)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "h3") {
		t.Fatalf("expected alpn h3 in %s", s)
	}
	if strings.Contains(s, `"utls"`) || strings.Contains(s, `"fingerprint"`) {
		t.Fatalf("uTLS must be omitted for xhttp QUIC/h3, got %s", s)
	}
}
