package ray2sing_test

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/option"
)

const fragmentFinalMask = `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"1-104","delay":"0","maxSplit":"0"}},{"type":"fragment","settings":{"packets":"1-1","length":"1-114","delay":"1","maxSplit":"11"}}]}`

func finalMaskOf(t *testing.T, link string) *option.FinalMaskOptions {
	t.Helper()
	options, err := ray2sing.Ray2SingboxOptions(context.Background(), link, false)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	var wrapper option.DialerOptionsWrapper
	if len(options.Outbounds) == 1 {
		wrapper = options.Outbounds[0].Options.(option.DialerOptionsWrapper)
	} else if len(options.Endpoints) == 1 {
		wrapper = options.Endpoints[0].Options.(option.DialerOptionsWrapper)
	} else {
		t.Fatalf("expected one outbound or endpoint")
	}
	return wrapper.TakeDialerOptions().FinalMask
}

func TestFinalMaskVless(t *testing.T) {
	link := "vless://25da296e-1d96-48ae-9867-4342796cd742@example.com:443?security=tls&sni=example.com&type=tcp&fm=" +
		url.QueryEscape(fragmentFinalMask) + "#fm"
	fm := finalMaskOf(t, link)
	if fm == nil || len(fm.TCP) != 2 || fm.TCP[0].Type != "fragment" || fm.TCP[1].Type != "fragment" || len(fm.UDP) != 0 {
		t.Fatalf("unexpected final mask: %+v", fm)
	}
	if !strings.Contains(string(fm.TCP[1].Settings), `"maxSplit":"11"`) {
		t.Fatalf("settings not kept: %s", fm.TCP[1].Settings)
	}

	// the converted config carries it as finalmask
	out, err := ray2sing.Ray2Singbox(context.Background(), link, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"finalmask"`) {
		t.Fatalf("finalmask missing from %s", out)
	}
}

func TestFinalMaskHysteria2UDP(t *testing.T) {
	fm := finalMaskOf(t, "hy2://pass@example.com:443?sni=example.com&fm="+
		url.QueryEscape(`{"udp":[{"type":"salamander","settings":{"password":"p"}}]}`)+"#hy2")
	if fm == nil || len(fm.UDP) != 1 || fm.UDP[0].Type != "salamander" {
		t.Fatalf("unexpected final mask: %+v", fm)
	}
}

func TestFinalMaskVmessJSON(t *testing.T) {
	for _, fmValue := range []string{fragmentFinalMask, `"` + strings.ReplaceAll(fragmentFinalMask, `"`, `\"`) + `"`} {
		vmess := `{"v":"2","ps":"fm","add":"example.com","port":"443","id":"25da296e-1d96-48ae-9867-4342796cd742","aid":"0","net":"tcp","tls":"tls","sni":"example.com","fm":` + fmValue + `}`
		fm := finalMaskOf(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(vmess)))
		if fm == nil || len(fm.TCP) != 2 {
			t.Fatalf("unexpected final mask for %s: %+v", fmValue, fm)
		}
	}
}

func TestFinalMaskAbsent(t *testing.T) {
	if fm := finalMaskOf(t, "vless://25da296e-1d96-48ae-9867-4342796cd742@example.com:443?security=tls&type=tcp#x"); fm != nil {
		t.Fatalf("unexpected final mask: %+v", fm)
	}
}

func TestFinalMaskInvalidIsRejected(t *testing.T) {
	for _, fm := range []string{`{"tcp":[{"type":"nope"}]}`, `{not json`} {
		_, err := ray2sing.Ray2SingboxOptions(context.Background(),
			"vless://25da296e-1d96-48ae-9867-4342796cd742@example.com:443?security=tls&type=tcp&fm="+url.QueryEscape(fm)+"#x", false)
		if err == nil {
			t.Fatalf("invalid fm %s accepted", fm)
		}
	}
}

// patterniha's merge mask, and dialMode=oob.<bytes> as an oob mask after it, next to the socket.
// The merge mask used to fail the whole link ("unknown mask type"), so the link was dropped.
func TestFinalMaskMergeAndDialModeOOB(t *testing.T) {
	fm := url.QueryEscape(`{"tcp": [{"type": "merge", "settings": {"times": 100, "delayMs": 30, "maxBytes": 16384}}]}`)
	link := "vless://dffb7646-1656-427a-8187-9c056a6a5fd5@[2a06:98c1:3101::6812:202f]:443?encryption=none&security=tls&type=ws&host=example.com&path=%2Fws&sni=example.com&fp=hellochrome_120&fm=" + fm + "&dialMode=oob.0&packetEncoding=xudp#oob"
	mask := finalMaskOf(t, link)
	if mask == nil || len(mask.TCP) != 2 || mask.TCP[0].Type != "merge" || mask.TCP[1].Type != "oob" || string(mask.TCP[1].Settings) != `{"bytes":[0]}` {
		t.Fatalf("finalmask: %+v", mask)
	}

	// dialMode alone, with several bytes
	mask = finalMaskOf(t, "vless://dffb7646-1656-427a-8187-9c056a6a5fd5@1.2.3.4:443?security=tls&sni=example.com&dialMode=oob.0,32,65#oob")
	if mask == nil || len(mask.TCP) != 1 || string(mask.TCP[0].Settings) != `{"bytes":[0,32,65]}` {
		t.Fatalf("finalmask: %+v", mask)
	}

	for _, mode := range []string{"oob.", "oob.256", "tfo"} {
		if _, err := ray2sing.Ray2SingboxOptions(context.Background(), "vless://dffb7646-1656-427a-8187-9c056a6a5fd5@1.2.3.4:443?security=tls&dialMode="+mode+"#x", false); err == nil {
			t.Errorf("dialMode=%s accepted", mode)
		}
	}
}
