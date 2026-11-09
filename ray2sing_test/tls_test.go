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

// As Xray, a cipher suite name sing-box does not know is skipped, not a reason to drop the outbound.
func TestTLSCipherSuitesUnknownSkipped(t *testing.T) {
	options, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), "trojan://pw@example.com:443?security=tls&fp=unsafe&cipherSuites=TLS_RSA_WITH_AES_128_CBC_SHA%3ANOT_A_SUITE%3ATLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256#t", false)
	if err != nil {
		t.Fatal(err)
	}
	if suites := options.Outbounds[0].Options.(*option.TrojanOutboundOptions).TLS.CipherSuites; len(suites) != 1 || suites[0] != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Fatalf("cipher suites %v", suites)
	}
}

// patterniha's links write cipherSuites as cs.
func TestTLSCipherSuitesShortKey(t *testing.T) {
	options, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), "vless://dffb7646-1656-427a-8187-9c056a6a5fd5@188.114.98.0:443?encryption=none&security=tls&type=ws&host=example.com&path=%2Fws&sni=example.com&fp=unsafe&cs=TLS_AES_256_GCM_SHA384%3ATLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384%3ATLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256#t", false)
	if err != nil {
		t.Fatal(err)
	}
	tls := options.Outbounds[0].Options.(*option.VLESSOutboundOptions).TLS
	if len(tls.CipherSuites) != 2 || tls.CipherSuites[0] != "TLS_AES_256_GCM_SHA384" || tls.CipherSuites[1] != "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" {
		t.Fatalf("cipher suites %v", tls.CipherSuites)
	}
}

// Without sni, the SNI is the transport host, then the server address (left to sing-box as empty).
func TestTLSServerNameFallsBackToHost(t *testing.T) {
	cases := []struct{ link, want string }{
		// CDN IP as address, domain only in host: the issue #2466 link shape
		{"vless://" + testUUID + "@104.16.1.1:443?type=ws&encryption=none&path=/ws&host=example.com&security=tls&fp=&alpn=http%2F1.1#t", "example.com"},
		// sni wins over host
		{"vless://" + testUUID + "@104.16.1.1:443?type=ws&path=/ws&host=example.com&sni=sni.example.com&security=tls#t", "sni.example.com"},
		// first of several hosts, port dropped
		{"vless://" + testUUID + "@104.16.1.1:443?type=ws&path=/ws&host=a.example.com%3A8443%2Cb.example.com&security=tls#t", "a.example.com"},
		// neither: sing-box uses the server address
		{"vless://" + testUUID + "@example.com:443?type=ws&path=/ws&security=tls#t", ""},
	}
	for _, c := range cases {
		tls := convertOne(t, c.link).Options.(*option.VLESSOutboundOptions).TLS
		if tls == nil || tls.ServerName != c.want {
			t.Errorf("%s: server_name %+v, want %q", c.link, tls, c.want)
		}
	}
}
