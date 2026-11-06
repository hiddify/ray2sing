package ray2sing

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

const hOVPNProfile = `# a profile as servers hand it out
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
comp-lzo
verb 3
key-direction 1
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUQ0FfY2VydGlmaWNhdGVfZm9yX3Rlc3RzMAoGCCqGSM49
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIBsTCCAVegAwIBAgIUQ2xpZW50X2NlcnRpZmljYXRlX2Zvcl90ZXN0czAKBggq
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgY2xpZW50X2tleQ==
-----END PRIVATE KEY-----
</key>
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
6acef03f62675b4b1bbd03e53b187727
-----END OpenVPN Static key V1-----
</tls-auth>
<auth-user-pass>
alice
secret
</auth-user-pass>
`

func hOpenVPN(t *testing.T, endpoint *T.Endpoint) *T.OpenVPNClientEndpointOptions {
	t.Helper()
	require.Equal(t, C.TypeOpenVPNClient, endpoint.Type)
	opts, ok := endpoint.Options.(*T.OpenVPNClientEndpointOptions)
	require.True(t, ok)
	return opts
}

func TestOpenVPNProfile(t *testing.T) {
	options, err := Ray2SingboxOptions(context.Background(), hOVPNProfile, false)
	require.NoError(t, err)
	require.Len(t, options.Endpoints, 1)
	endpoint := options.Endpoints[0]
	require.Equal(t, "vpn.example.com § 0", endpoint.Tag, "named after its server")
	opts := hOpenVPN(t, &endpoint)

	require.Equal(t, "tls", opts.Mode)
	require.Equal(t, "vpn.example.com", opts.Server)
	require.EqualValues(t, 1194, opts.ServerPort)
	require.Equal(t, "udp", opts.Network)
	require.Equal(t, "SHA256", opts.Auth)
	require.Equal(t, "adaptive", opts.CompressionLZO)
	require.Empty(t, opts.Cipher, "cipher is not allowed in TLS mode")
	require.Equal(t, "AES-256-CBC", opts.DataCiphersFallback)
	require.Equal(t, []string{"AES-256-CBC"}, []string(opts.DataCiphers))
	require.Equal(t, "alice", opts.Username)
	require.Equal(t, "secret", opts.Password)

	require.NotNil(t, opts.TLS)
	require.Equal(t, "server", opts.TLS.RemoteCertificateTLS)
	require.Equal(t, "-----BEGIN CERTIFICATE-----", opts.TLS.Certificate[0], "the PEM lines as they are, not decoded")
	require.Len(t, opts.TLS.ClientCertificate, 3)
	require.Len(t, opts.TLS.ClientKey, 3)
	require.NotNil(t, opts.TLS.ControlWrap)
	require.Equal(t, "tls_auth", opts.TLS.ControlWrap.Type)
	require.Equal(t, "client", opts.TLS.ControlWrap.Direction, "key-direction 1")
	require.Len(t, opts.TLS.ControlWrap.Key, 3)

	out, err := Ray2Singbox(context.Background(), hOVPNProfile, false)
	require.NoError(t, err)
	require.Contains(t, string(out), `"type":"openvpn-client"`)
}

func TestOpenVPNLink(t *testing.T) {
	profile := strings.Replace(hOVPNProfile, "<auth-user-pass>\nalice\nsecret\n</auth-user-pass>\n", "", 1)
	profile = strings.Replace(profile, "<tls-auth>", "<tls-crypt>", 1)
	profile = strings.Replace(profile, "</tls-auth>", "</tls-crypt>", 1)
	profile = strings.Replace(profile, "proto udp\n", "proto tcp-client\n", 1)
	link := "ovpn://" + base64.StdEncoding.EncodeToString([]byte(profile)) + "?user=bob&pass=p%40ss#My%20VPN"

	options, err := Ray2SingboxOptions(context.Background(), link+"\nvless://id@example.org:443?security=tls#other", false)
	require.NoError(t, err)
	require.Len(t, options.Endpoints, 1, "the link beside other links")
	require.Len(t, options.Outbounds, 1)
	endpoint := options.Endpoints[0]
	require.True(t, strings.HasPrefix(endpoint.Tag, "My VPN § "), endpoint.Tag)
	opts := hOpenVPN(t, &endpoint)
	require.Equal(t, "tcp", opts.Network)
	require.Equal(t, "bob", opts.Username, "the credentials of the link, as the profile has none inline")
	require.Equal(t, "p@ss", opts.Password)
	require.Equal(t, "tls_crypt", opts.TLS.ControlWrap.Type)
	require.Empty(t, opts.TLS.ControlWrap.Direction, "tls-crypt has no direction")

	// the link's base64 may be URL-safe and unpadded
	link = "ovpn://" + base64.RawURLEncoding.EncodeToString([]byte(profile))
	endpoint2, err := OpenVPNSingbox(link)
	require.NoError(t, err)
	require.Equal(t, "vpn.example.com", endpoint2.Tag)
}

func TestOpenVPNRemotesAndStaticKey(t *testing.T) {
	profile := `client
dev tun
proto udp
port 1195
remote a.example.com
remote b.example.com 443 tcp
remote-random
cipher AES-256-CBC
secret [inline] 1
<secret>
-----BEGIN OpenVPN Static key V1-----
6acef03f62675b4b1bbd03e53b187727
-----END OpenVPN Static key V1-----
</secret>
`
	endpoint, err := ParseOVPN(profile, "", "", "")
	require.NoError(t, err)
	opts := hOpenVPN(t, endpoint)
	require.Empty(t, opts.Server)
	require.Len(t, opts.Servers, 2)
	require.Equal(t, "a.example.com", opts.Servers[0].Server)
	require.EqualValues(t, 1195, opts.Servers[0].ServerPort, "the profile's port")
	require.Equal(t, "udp", opts.Servers[0].Network, "the profile's proto")
	require.EqualValues(t, 443, opts.Servers[1].ServerPort)
	require.Equal(t, "tcp", opts.Servers[1].Network)
	require.True(t, opts.RemoteRandom)

	require.Equal(t, "static_key", opts.Mode)
	require.Equal(t, "AES-256-CBC", opts.Cipher, "cipher is the static key's")
	require.Equal(t, "client", opts.KeyDirection)
	require.Len(t, opts.StaticKey, 3)
	require.Nil(t, opts.TLS)
}

func TestOpenVPNRefusesWhatItCannotRun(t *testing.T) {
	_, err := ParseOVPN(strings.Replace(hOVPNProfile, "dev tun", "dev tap", 1), "", "", "")
	require.ErrorContains(t, err, "tap")

	_, err = ParseOVPN("client\ndev tun\nremote a.example.com\nca ca.crt\n", "", "", "")
	require.ErrorContains(t, err, "<ca>", "a certificate in a file beside it can not be read")

	_, err = ParseOVPN("client\ndev tun\n", "", "", "")
	require.ErrorContains(t, err, "remote")
}

func TestOpenVPNProfileDetection(t *testing.T) {
	require.True(t, isOpenVPNProfile(hOVPNProfile))
	require.False(t, isOpenVPNProfile("vless://id@remote.example.com:443#remote x"))
	require.False(t, isOpenVPNProfile("[Interface]\nPrivateKey = a2V5\n[Peer]\nEndpoint = 1.2.3.4:51820"))
	require.False(t, isOpenVPNProfile("remote 1.2.3.4"), "one line alone is not enough")
}
