package ray2sing_test

import (
	"net/url"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// An XDRIVE link carries Xray's xdriveSettings as JSON in xdrive=, with VLESS encryption.
func TestXDriveLink(t *testing.T) {
	settings := `{"service":"google-drive","remoteFolder":"1AbC","secrets":["id","secret","token"],"pollIntervalMs":100,"xmux":{"maxConnections":"2-4"},"address":"216.239.38.120","port":443}`
	link := "vless://dffb7646-1656-427a-8187-9c056a6a5fd5@127.0.0.1:1?encryption=mlkem768x25519plus.native.0rtt.9zy0chrl2-czYBSv11y34twAmvJlMoJIDhhMGc--lDo&security=tls&fp=chrome&type=xdrive&xdrive=" + url.QueryEscape(settings) + "#xdrive"
	options, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), link, false)
	if err != nil {
		t.Fatal(err)
	}
	vless := options.Outbounds[0].Options.(*option.VLESSOutboundOptions)
	if vless.Transport == nil || vless.Transport.Type != C.V2RayTransportTypeXDrive {
		t.Fatalf("transport %+v", vless.Transport)
	}
	xdrive := vless.Transport.XDriveOptions
	if xdrive.Service != "google-drive" || xdrive.RemoteFolder != "1AbC" || len(xdrive.Secrets) != 3 || xdrive.PollIntervalMs != 100 {
		t.Fatalf("xdrive %+v", xdrive)
	}
	if xdrive.Xmux == nil || xdrive.Xmux.MaxConnections.From != 2 || xdrive.Xmux.MaxConnections.To != 4 {
		t.Fatalf("xmux %+v", xdrive.Xmux)
	}
	if xdrive.FrontingAddress != "216.239.38.120" || xdrive.FrontingPort != 443 {
		t.Fatalf("fronting %s:%d", xdrive.FrontingAddress, xdrive.FrontingPort)
	}
	if vless.Encryption == "" {
		t.Fatal("encryption dropped")
	}

	if _, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), "vless://dffb7646-1656-427a-8187-9c056a6a5fd5@127.0.0.1:1?type=xdrive#x", false); err == nil {
		t.Fatal("a link without xdrive= must fail")
	}
}
