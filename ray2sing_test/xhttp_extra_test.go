package ray2sing_test

import (
	"net/url"
	"testing"
)

// Xray writes the XHTTP extra in camelCase (xPaddingKey, scMaxEachPostBytes, noGRPCHeader, xmux's
// hMaxRequestTimes, downloadSettings' tlsSettings.serverName...); every value reaches the sing-box
// options, whose keys are snake_case. Header names are kept as written. hiddify-app#2479
func TestXHTTPExtraCamelCase(t *testing.T) {
	extra := `{"xPaddingHeader":"9267f8","xPaddingKey":"_826c26","xPaddingMethod":"tokenish","xPaddingObfsMode":true,` +
		`"xPaddingPlacement":"header","xPaddingBytes":"250-950","scMaxEachPostBytes":"500000-1000000","noGRPCHeader":true,` +
		`"uplinkHTTPMethod":"PUT","headers":{"User-Agent":"curl/8","X-Custom":"1"},` +
		`"xmux":{"maxConcurrency":"16-32","cMaxReuseTimes":"0","hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000","hKeepAlivePeriod":60},` +
		`"downloadSettings":{"address":"dl.example.com","port":8443,"security":"tls","tlsSettings":{"serverName":"dl.example.com","allowInsecure":true,"alpn":["h2"],"fingerprint":"chrome"},` +
		`"xhttpSettings":{"path":"/down","host":"dl.example.com"},"xPaddingKey":"dlkey"}}`
	got := convert(t, "vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443?type=xhttp&mode=stream-one&security=tls&fp=firefox&sni=example.com&path=%2Fx&extra="+
		url.QueryEscape(extra)+"#t")
	wantAll(t, got,
		`"x_padding_header":"9267f8"`, `"x_padding_key":"_826c26"`, `"x_padding_method":"tokenish"`,
		`"x_padding_obfs_mode":true`, `"x_padding_placement":"header"`, `"x_padding_bytes":"250-950"`,
		`"sc_max_each_post_bytes":"500000-1000000"`, `"no_grpc_header":true`, `"uplink_http_method":"PUT"`,
		`"User-Agent":"curl/8"`, `"X-Custom":"1"`,
		`"max_concurrency":"16-32"`, `"h_max_request_times":"600-900"`, `"h_max_reusable_secs":"1800-3000"`, `"h_keep_alive_period":60`,
		`"server":"dl.example.com"`, `"server_port":8443`, `"path":"/down"`, `"x_padding_key":"dlkey"`,
		`"server_name":"dl.example.com"`, `"insecure":true`,
	)
}

// sing-box style snake_case keys in extra keep working.
func TestXHTTPExtraSnakeCase(t *testing.T) {
	extra := `{"x_padding_key":"k1","x_padding_method":"tokenish","x_padding_obfs_mode":true}`
	got := convert(t, "vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443?type=xhttp&mode=packet-up&security=tls&sni=example.com&path=%2Fx&extra="+
		url.QueryEscape(extra)+"#t")
	wantAll(t, got, `"x_padding_key":"k1"`, `"x_padding_method":"tokenish"`, `"x_padding_obfs_mode":true`)
}
