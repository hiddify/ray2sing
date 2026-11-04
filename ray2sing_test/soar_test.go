package ray2sing_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hiddify/ray2sing/ray2sing"
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func soarTestKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func soarOptions(t *testing.T, link string) (*T.Outbound, *T.SoarOptions) {
	t.Helper()
	out, err := ray2sing.SoarSingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != C.TypeSoar {
		t.Fatalf("type %q", out.Type)
	}
	return out, out.Options.(*T.SoarOptions)
}

// The URL form: the key in the query or before the "@", the outbound's fields as parameters.
func TestSoarLink(t *testing.T) {
	pub := soarTestKey(t)
	std := base64.StdEncoding.EncodeToString(pub)

	link := "soar://t.example.com?pk=" + url.QueryEscape(std) + "&resolvers=8.8.8.8,1.1.1.1:5353&country=IR&sample_ranges=16&tcp=on&safe_qname=101&max_qname=200&max_answer=512&hold=800ms&max_inflight=64&max_path_window=8&max_streams=32&stream_window=131072&session_idle=60&connect_timeout=30s&discovery_want=4&discovery_pace=0.1#My%20Soar"
	out, o := soarOptions(t, link)
	d := o.SmartPool.DiscoveryOptions()
	if out.Tag != "My Soar" || o.Domain != "t.example.com" || o.PublicKey != std || strings.Join(o.Resolvers, ",") != "8.8.8.8,1.1.1.1:5353" ||
		!o.SmartPool.IsEnabledOr(false) || d.Country != "ir" || d.SampleRanges != 16 || o.TCP != "on" || o.SafeQName != 101 || o.MaxQName != 200 || o.MaxAnswer != 512 ||
		time.Duration(o.Hold) != 800*time.Millisecond || o.MaxInflight != 64 || o.MaxPathWindow != 8 || o.MaxStreams != 32 || o.StreamWindow != 131072 ||
		time.Duration(o.SessionIdle) != time.Minute || time.Duration(o.ConnectTimeout) != 30*time.Second || d.Want != 4 ||
		time.Duration(d.Pace) != 100*time.Millisecond {
		t.Fatalf("options: %+v", o)
	}

	// an unescaped "+" of the key arrives as a space and is put back
	_, o = soarOptions(t, "soar://t.example.com?pk="+std)
	if o.PublicKey != std || len(o.Resolvers) != 0 {
		t.Fatalf("raw key: %+v", o)
	}

	// the key before the "@", base64url; smart_pool=0 turns the pool off, discovery=1 adds "auto"
	raw := base64.RawURLEncoding.EncodeToString(pub)
	out, o = soarOptions(t, "soar://"+raw+"@t.example.com?resolver=9.9.9.9&smart_pool=0&discovery=1")
	if out.Tag != "soar" || o.PublicKey != raw || strings.Join(o.Resolvers, ",") != "9.9.9.9,auto" || o.SmartPool == nil || o.SmartPool.Enabled {
		t.Fatalf("user key: %+v", o)
	}
	_, o = soarOptions(t, "soar://t.example.com?pk="+raw+"&smart_pool=weighted")
	if !o.SmartPool.IsEnabled() || o.SmartPool.LoadBalance != "weighted" {
		t.Fatalf("strategy: %+v", o.SmartPool)
	}

	for _, bad := range []string{
		"soar://t.example.com",
		"soar://t.example.com?pk=short",
		"soar://?pk=" + raw,
	} {
		if _, err := ray2sing.SoarSingbox(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// The profile link WhiteDNS exports for Soar: base64url JSON, schema "whitedns.profile".
func TestSoarWhiteDNSLink(t *testing.T) {
	pub := soarTestKey(t)
	key := base64.StdEncoding.EncodeToString(pub)
	doc := `{"schema":"whitedns.profile","version":1,"profile":{"name":"Soar IR","server":{"domain":"t.example.com","public_key":"` + key + `"},` +
		`"soarSettings":{"transport":"auto","discovery":true,"country":"IR","discoveryWant":2,"discoveryConcurrency":2,"discoveryPaceMs":1000,"safeQName":101,"maxQName":253,"maxAnswer":1232,"holdMs":500,"maxInflight":128,"maxPathWindow":32,"maxStreams":128,"streamWindowKiB":256,"sendBufferKiB":64,"sessionIdleSeconds":90,"dialTimeoutSeconds":90},` +
		`"resolvers":["2.188.21.130","5.202.100.100:53"]}}`
	link := "soar://" + base64.RawURLEncoding.EncodeToString([]byte(doc))
	out, o := soarOptions(t, link)
	d := o.SmartPool.DiscoveryOptions()
	if out.Tag != "Soar IR" || o.Domain != "t.example.com" || o.PublicKey != key || strings.Join(o.Resolvers, ",") != "2.188.21.130,5.202.100.100:53,auto" ||
		!o.SmartPool.IsEnabledOr(false) || d.Country != "ir" || o.TCP != "auto" || d.Want != 2 || d.Concurrency != 2 || time.Duration(d.Pace) != time.Second ||
		o.SafeQName != 101 || o.MaxQName != 253 || o.MaxAnswer != 1232 || time.Duration(o.Hold) != 500*time.Millisecond || o.MaxInflight != 128 ||
		o.MaxPathWindow != 32 || o.MaxStreams != 128 || o.StreamWindow != 256*1024 || o.SendBuffer != 64*1024 ||
		time.Duration(o.SessionIdle) != 90*time.Second || time.Duration(o.ConnectTimeout) != 90*time.Second {
		t.Fatalf("options: %+v", o)
	}

	// GLOBAL (no country), discovery off, no resolvers: WhiteDNS's one resolver
	doc = `{"schema":"whitedns.profile","version":1,"profile":{"name":"G","server":{"domain":"t.example.com","public_key":"` + key + `"},"soarSettings":{"discovery":false,"country":""}}}`
	_, o = soarOptions(t, "soar://"+base64.RawURLEncoding.EncodeToString([]byte(doc))+"#Renamed")
	if o.SmartPool.DiscoveryOptions().Country != "" || strings.Join(o.Resolvers, ",") != "1.1.1.1" {
		t.Fatalf("global: %+v", o)
	}

	// no soarSettings: WhiteDNS's defaults, discovery for Iran
	doc = `{"schema":"whitedns.profile","version":1,"profile":{"name":"D","server":{"domain":"t.example.com","public_key":"` + key + `"}}}`
	_, o = soarOptions(t, "soar://"+base64.StdEncoding.EncodeToString([]byte(doc)))
	if o.SmartPool.DiscoveryOptions().Country != "ir" || len(o.Resolvers) != 0 {
		t.Fatalf("defaults: %+v", o)
	}

	// through the whole conversion
	options, err := ray2sing.Ray2SingboxOptions(context.Background(), link, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Outbounds) != 1 || options.Outbounds[0].Type != C.TypeSoar || options.Outbounds[0].Tag != "Soar IR § 0" {
		t.Fatalf("outbounds: %+v", options.Outbounds)
	}
}

// The discovery parameters of a dnstt link go into its smart_pool block, the pool off unless asked.
func TestDnsttLinkDiscovery(t *testing.T) {
	out, err := ray2sing.DnsttSingbox("dnstt://v.example.com?domain=v.example.com&pubkey=00&resolver=auto&country=ru&sample_ranges=4")
	if err != nil {
		t.Fatal(err)
	}
	o := out.Options.(*T.DnsttOptions)
	if o.SmartPool == nil || o.SmartPool.Enabled || o.SmartPool.DiscoveryOptions().Country != "ru" || o.SmartPool.DiscoveryOptions().SampleRanges != 4 {
		t.Fatalf("smart_pool: %+v", o.SmartPool)
	}
	out, _ = ray2sing.DnsttSingbox("dnstt://v.example.com?domain=v.example.com&pubkey=00&resolver=auto")
	if out.Options.(*T.DnsttOptions).SmartPool != nil {
		t.Fatal("a pool block without asking")
	}
}
