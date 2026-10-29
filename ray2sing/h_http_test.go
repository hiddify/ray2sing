package ray2sing

import (
	"testing"

	T "github.com/sagernet/sing-box/option"
)

// A subscription URL in a profile became an HTTP proxy with port 0.
func TestHTTPLinkWithoutPort(t *testing.T) {
	if _, err := HttpsSingbox("https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_1.txt"); err == nil {
		t.Fatal("a subscription URL is not an HTTP proxy")
	}
	if out, err := HttpsSingbox("https://user:pass@proxy.example.com:8443#p"); err != nil || out.Options.(*T.HTTPOutboundOptions).ServerPort != 8443 {
		t.Fatalf("HTTP proxy: %v %+v", err, out)
	}
}
