package ray2sing_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/hiddify/ray2sing/ray2sing"
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func TestMasterdnsLink(t *testing.T) {
	url := "masterdns://v.example.com?key=0123456789abcdef0123456789abcdef&resolvers=8.8.8.8,1.1.1.1:5353,10.0.0.0/30&encryption=aes-256-gcm&mode=tcp&balancing=least-loss&dup=3&setup_dup=4&ucomp=zstd&dcomp=2&base_encode=1&min_upload_mtu=40&max_upload_mtu=160&max_download_mtu=900&mtu_test_timeout=1.5&mtu_test_retries=3&auto_remove_low_mtu_resolvers=false&workers=2&arq_window=700&ready_timeout=10s&connect_timeout=20&log_level=DEBUG&uot=1#My%20Tunnel"
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "masterdns",
			"tag": "My Tunnel § 0",
			"domains": ["v.example.com"],
			"resolvers": ["8.8.8.8", "1.1.1.1:5353", "10.0.0.0/30"],
			"encryption": "aes-256-gcm",
			"key": "0123456789abcdef0123456789abcdef",
			"mode": "tcp",
			"balancing": "least-loss",
			"packet_duplication": 3,
			"setup_packet_duplication": 4,
			"upload_compression": "zstd",
			"download_compression": "lz4",
			"base_encode": true,
			"min_upload_mtu": 40,
			"max_upload_mtu": 160,
			"max_download_mtu": 900,
			"mtu_test_timeout": "1.5s",
			"mtu_test_retries": 3,
			"auto_remove_low_mtu_resolvers": false,
			"workers": 2,
			"arq_window": 700,
			"ready_timeout": "10s",
			"connect_timeout": "20s",
			"log_level": "debug",
			"udp_over_tcp": {"enabled": true}
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}

// The key may stand before the "@", and a minimal link keeps every default.
func TestMasterdnsKeyLink(t *testing.T) {
	out, err := ray2sing.MasterdnsSingbox("masterdns://secret-key@v.example.com?resolver=9.9.9.9#dns")
	if err != nil {
		t.Fatal(err)
	}
	options := out.Options.(*T.MasterDNSOptions)
	if out.Type != C.TypeMasterDNS || out.Tag != "dns" || options.Key != "secret-key" || len(options.Domains) != 1 || options.Domains[0] != "v.example.com" ||
		len(options.Resolvers) != 1 || options.Resolvers[0] != "9.9.9.9" || options.Encryption != "" || options.Mode != "" || options.UDPOverTCP != nil {
		t.Fatalf("options: %+v", options)
	}
	if !options.SmartPool.IsEnabled() {
		t.Fatal("the smart pool is on by default")
	}
	// no resolvers: the built-in list through the pool, or public resolvers without it
	out, err = ray2sing.MasterdnsSingbox("masterdns://v.example.com?key=k")
	if err != nil {
		t.Fatal(err)
	}
	if o := out.Options.(*T.MasterDNSOptions); !o.SmartPool.IsEnabled() || strings.Join(o.Resolvers, ",") != "auto" {
		t.Fatalf("no resolvers: %+v", o)
	}
	out, err = ray2sing.MasterdnsSingbox("masterdns://v.example.com?key=k&smart_pool=0")
	if err != nil {
		t.Fatal(err)
	}
	if o := out.Options.(*T.MasterDNSOptions); o.SmartPool != nil || len(o.Resolvers) != 8 || o.Resolvers[0] != "8.8.8.8" {
		t.Fatalf("no resolvers, no pool: %+v", o)
	}
	// a range is for the MasterDnsVPN client: no pool unless asked; a strategy turns it on
	out, _ = ray2sing.MasterdnsSingbox("masterdns://v.example.com?key=k&resolvers=8.8.8.8,10.0.0.0/30")
	if out.Options.(*T.MasterDNSOptions).SmartPool != nil {
		t.Fatal("a range turned the pool on")
	}
	out, _ = ray2sing.MasterdnsSingbox("masterdns://v.example.com?key=k&smart_pool=weighted&pretest_domain=example.org&country=IR&discovery_want=5")
	if o := out.Options.(*T.MasterDNSOptions); !o.SmartPool.IsEnabled() || o.SmartPool.LoadBalance != "weighted" || o.PreTestDomain != "example.org" ||
		o.SmartPool.DiscoveryOptions().Country != "ir" || o.SmartPool.DiscoveryOptions().Want != 5 {
		t.Fatalf("strategy: %+v", o)
	}
	if _, err := ray2sing.MasterdnsSingbox("masterdns://?key=k&resolvers=8.8.8.8"); err == nil {
		t.Fatal("a link without a domain was accepted")
	}
}

// The MasterDnsVPN client's own JSON configuration (its -json_base64 form) with a RESOLVERS list.
func TestMasterdnsJSONLink(t *testing.T) {
	doc := `{"DOMAINS":["v.example.com","w.example.com"],"ENCRYPTION_KEY":"abc","DATA_ENCRYPTION_METHOD":2,"PROTOCOL_TYPE":"SOCKS5","RESOLVERS":["8.8.8.8","1.1.1.1:5353"],"RESOLVER_BALANCING_STRATEGY":3,"PACKET_DUPLICATION_COUNT":2,"UPLOAD_COMPRESSION_TYPE":1,"MTU_TEST_TIMEOUT":2.0,"AUTO_DISABLE_TIMEOUT_SERVERS":false,"RX_TX_WORKERS":4,"NAME":"from json"}`
	link := "masterdns://" + base64.StdEncoding.EncodeToString([]byte(doc))
	options, err := ray2sing.Ray2SingboxOptions(context.Background(), link, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Outbounds) != 1 {
		t.Fatalf("outbounds: %+v", options.Outbounds)
	}
	out := options.Outbounds[0]
	o := out.Options.(*T.MasterDNSOptions)
	if out.Tag != "from json § 0" || len(o.Domains) != 2 || o.Domains[1] != "w.example.com" || o.Key != "abc" || o.Encryption != "2" || o.Mode != "socks5" ||
		len(o.Resolvers) != 2 || o.Resolvers[1] != "1.1.1.1:5353" || o.Balancing != "3" || o.PacketDuplication != 2 || o.UploadCompression != "zstd" ||
		time.Duration(o.MTUTestTimeout) != 2*time.Second || o.AutoDisableTimeoutResolvers == nil || *o.AutoDisableTimeoutResolvers || o.Workers != 4 {
		t.Fatalf("options: %+v", o)
	}
	// the fragment names it
	out2, err := ray2sing.MasterdnsSingbox(link + "#Named%20One")
	if err != nil || out2.Tag != "Named One" {
		t.Fatalf("%v %q", err, out2.Tag)
	}
}

// The profile link of WhiteDNS (schema "whitedns.profile") for MasterDnsVPN.
func TestMasterdnsWhiteDNSLink(t *testing.T) {
	doc := `{"schema":"whitedns.profile","version":1,"profile":{"name":"Tehran","server":{"domain":"v.example.com.","encryption_key":"k3y","encryption_method":2}}}`
	link := "masterdns://" + base64.RawURLEncoding.EncodeToString([]byte(doc))
	out, err := ray2sing.MasterdnsSingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	o := out.Options.(*T.MasterDNSOptions)
	if out.Tag != "Tehran" || strings.Join(o.Domains, ",") != "v.example.com" || o.Key != "k3y" || o.Encryption != "2" || !o.SmartPool.IsEnabled() || strings.Join(o.Resolvers, ",") != "auto" {
		t.Fatalf("options: %+v", o)
	}
	if out, err = ray2sing.MasterdnsSingbox(link + "#Other"); err != nil || out.Tag != "Other" {
		t.Fatalf("%v %+v", err, out)
	}
}
