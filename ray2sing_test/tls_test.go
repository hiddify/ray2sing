package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// Xray's cipherSuites, with fp=unsafe (the standard TLS client, which applies them).
func TestTLSCipherSuites(t *testing.T) {
	options, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), "trojan://pw@example.com:443?security=tls&type=ws&path=%2Fws&fp=unsafe&cipherSuites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256%3ATLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256#t", false)
	if err != nil {
		t.Fatal(err)
	}
	tls := options.Outbounds[0].Options.(*option.TrojanOutboundOptions).TLS
	if len(tls.CipherSuites) != 2 || tls.CipherSuites[1] != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" || tls.UTLS == nil || tls.UTLS.Fingerprint != "unsafe" {
		t.Fatalf("cipher suites %v, utls %+v", tls.CipherSuites, tls.UTLS)
	}
}
