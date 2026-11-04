package ray2sing_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/hiddify/ray2sing/ray2sing"
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

const dnstPubKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func convertDnst(t *testing.T, link string) []T.Outbound {
	t.Helper()
	options, err := ray2sing.Ray2SingboxOptions(context.Background(), link, false)
	if err != nil {
		t.Fatalf("%s: %v", link, err)
	}
	return options.Outbounds
}

// DNSTT + SOCKS: a socks outbound through a dnstt outbound in the original wire format, with the
// built-in resolvers.
func TestDnstDnsttSocks(t *testing.T) {
	outs := convertDnst(t, "dnst://t.example.com/dnstt/socks?pubkey="+dnstPubKey+"&user=foo&password=bar#my-tunnel")
	if len(outs) != 2 || outs[0].Type != C.TypeDNSTT || outs[1].Type != C.TypeSOCKS {
		t.Fatalf("outbounds: %+v", outs)
	}
	dnstt := outs[0].Options.(*T.DnsttOptions)
	socks := outs[1].Options.(*T.SOCKSOutboundOptions)
	if dnstt.Domain != "t.example.com" || dnstt.PublicKey != dnstPubKey || !dnstt.DnsttCompat || len(dnstt.Resolvers) != 1 || dnstt.Resolvers[0] != "auto" {
		t.Fatalf("dnstt: %+v", dnstt)
	}
	if socks.Username != "foo" || socks.Password != "bar" || socks.Detour != outs[0].Tag || !strings.HasPrefix(outs[1].Tag, "my-tunnel") || !strings.Contains(outs[0].Tag, "§hide§") {
		t.Fatalf("socks: %s %+v", outs[1].Tag, socks)
	}
}

// VayDNS + SSH: the VayDNS wire fields, the durations, an extension parameter (resolver) and an
// ssh outbound in front.
func TestDnstVaydnsSSH(t *testing.T) {
	outs := convertDnst(t, "dnst://t.example.com/vaydns/ssh?pubkey="+dnstPubKey+"&record-type=cname&clientid-size=4&keepalive=10s&idle-timeout=60s&resolver=8.8.8.8:53,dot://1.1.1.1:853&user=tunnel&password=s3cret#vay")
	if len(outs) != 2 || outs[0].Type != C.TypeDNSTT || outs[1].Type != C.TypeSSH {
		t.Fatalf("outbounds: %+v", outs)
	}
	dnstt := outs[0].Options.(*T.DnsttOptions)
	if dnstt.DnsttCompat || dnstt.RecordType != "cname" || *dnstt.ClientIDSize != 4 || time.Duration(*dnstt.KeepAlive) != 10*time.Second || time.Duration(*dnstt.IdleTimeout) != 60*time.Second ||
		strings.Join(dnstt.Resolvers, " ") != "8.8.8.8:53 dot://1.1.1.1:853" {
		t.Fatalf("dnstt: %+v", dnstt)
	}
	ssh := outs[1].Options.(*T.SSHOutboundOptions)
	if ssh.User != "tunnel" || ssh.Password != "s3cret" || ssh.Detour != outs[0].Tag || len(ssh.PrivateKey) != 0 {
		t.Fatalf("ssh: %+v", ssh)
	}

	// dnstt-compat is honoured when written
	outs = convertDnst(t, "dnst://t.example.com/vaydns/socks?pubkey="+dnstPubKey+"&record-type=txt&dnstt-compat=true#x")
	if !outs[0].Options.(*T.DnsttOptions).DnsttCompat {
		t.Fatal("dnstt-compat=true not carried")
	}
}

// An SSH private key is base64url of the PEM body in the URL form; it becomes a PEM with the
// matching header.
func TestDnstSSHPrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pk := base64.RawURLEncoding.EncodeToString(der)
	outs := convertDnst(t, "dnst://t.example.com/dnstt/ssh?pubkey="+dnstPubKey+"&user=tunnel&pk="+pk+"#k")
	ssh := outs[1].Options.(*T.SSHOutboundOptions)
	if len(ssh.PrivateKey) != 1 || !strings.HasPrefix(ssh.PrivateKey[0], "-----BEGIN PRIVATE KEY-----\n") || !strings.Contains(ssh.PrivateKey[0], "\n-----END PRIVATE KEY-----") || ssh.Password != "" {
		t.Fatalf("ssh: %+v", ssh)
	}
	if _, err := ray2sing.DnstSingbox("dnst://t.example.com/dnstt/ssh?pubkey=" + dnstPubKey + "&user=u&pk=bm90LWEta2V5"); err == nil || !strings.Contains(err.Error(), "pk") {
		t.Fatalf("bad key accepted: %v", err)
	}
}

// Shadowsocks behind the tunnel.
func TestDnstShadowsocks(t *testing.T) {
	outs := convertDnst(t, "dnst://t.example.com/dnstt/shadowsocks?pubkey="+dnstPubKey+"&method=aes-256-gcm&password=secret#ss")
	ss := outs[1].Options.(*T.ShadowsocksOutboundOptions)
	if outs[1].Type != C.TypeShadowsocks || ss.Method != "aes-256-gcm" || ss.Password != "secret" || ss.Detour != outs[0].Tag {
		t.Fatalf("ss: %+v", ss)
	}
}

// MasterDNS + SOCKS is the masterdns outbound alone (the server connects to the destination),
// with the built-in resolvers through its smart pool; custom is the server's TCP mode; a backend
// goes in front of it.
func TestDnstMasterdns(t *testing.T) {
	outs := convertDnst(t, "dnst://v.example.com/masterdns/socks?mkey=abcdef1234&encryption=5&user=foo&password=bar#md")
	if len(outs) != 1 || outs[0].Type != C.TypeMasterDNS || outs[0].Tag != "md § 0" {
		t.Fatalf("outbounds: %+v", outs)
	}
	md := outs[0].Options.(*T.MasterDNSOptions)
	if md.Key != "abcdef1234" || md.Encryption != "5" || md.Mode != "" || len(md.Domains) != 1 || md.Domains[0] != "v.example.com" || strings.Join(md.Resolvers, ",") != "auto" || !md.SmartPool.IsEnabled() {
		t.Fatalf("masterdns: %+v", md)
	}

	outs = convertDnst(t, "dnst://v.example.com/masterdns/custom?mkey=abcdef1234&encryption=1&resolvers=9.9.9.9,10.0.0.0/30#tcp")
	md = outs[0].Options.(*T.MasterDNSOptions)
	if len(outs) != 1 || md.Mode != "tcp" || strings.Join(md.Resolvers, " ") != "9.9.9.9 10.0.0.0/30" {
		t.Fatalf("custom: %+v", md)
	}

	outs = convertDnst(t, "dnst://v.example.com/masterdns/ssh?mkey=abcdef1234&encryption=2&user=root&password=pw#mssh")
	if len(outs) != 2 || outs[0].Type != C.TypeMasterDNS || outs[1].Type != C.TypeSSH || outs[0].Options.(*T.MasterDNSOptions).Mode != "tcp" || outs[1].Options.(*T.SSHOutboundOptions).Detour != outs[0].Tag {
		t.Fatalf("ssh: %+v", outs)
	}

	if _, err := ray2sing.DnstSingbox("dnst://v.example.com/masterdns/socks?encryption=5"); err == nil {
		t.Fatal("missing mkey accepted")
	}
	outs = convertDnst(t, "dnst://v.example.com/masterdns/socks?encryption=0#plain")
	if outs[0].Options.(*T.MasterDNSOptions).Encryption != "0" {
		t.Fatal("encryption none needs no key")
	}
}

// The base64url JSON form, with a PEM private key stored as is.
func TestDnstJSONForm(t *testing.T) {
	doc := `{"tag":"json tunnel","transport":{"type":"vaydns","domain":"t.example.com","pubkey":"` + dnstPubKey + `","record_type":"txt","dnstt_compat":false,"clientid_size":2,"idle_timeout":"60s","keepalive":"10s"},"backend":{"type":"ssh","user":"tunnel","password":"secret"}}`
	link := "dnst://" + base64.RawURLEncoding.EncodeToString([]byte(doc))
	outs := convertDnst(t, link)
	if len(outs) != 2 || outs[0].Type != C.TypeDNSTT || outs[1].Type != C.TypeSSH || !strings.HasPrefix(outs[1].Tag, "json tunnel") {
		t.Fatalf("outbounds: %+v", outs)
	}
	dnstt := outs[0].Options.(*T.DnsttOptions)
	if dnstt.DnsttCompat || dnstt.RecordType != "txt" || *dnstt.ClientIDSize != 2 || time.Duration(*dnstt.IdleTimeout) != time.Minute {
		t.Fatalf("dnstt: %+v", dnstt)
	}

	doc = `{"tag":"m","transport":{"type":"masterdns","domain":"v.example.com","mkey":"k","encryption":1},"backend":{"type":"custom"}}`
	outs = convertDnst(t, "dnst://"+base64.RawURLEncoding.EncodeToString([]byte(doc)))
	if len(outs) != 1 || outs[0].Type != C.TypeMasterDNS || outs[0].Options.(*T.MasterDNSOptions).Mode != "tcp" || outs[0].Options.(*T.MasterDNSOptions).Encryption != "1" {
		t.Fatalf("masterdns json: %+v", outs)
	}

	// the spec's own example: slipstream is refused with a reason
	specExample := "dnst://eyJ0YWciOiJteS10dW5uZWwiLCJ0cmFuc3BvcnQiOnsidHlwZSI6InNsaXBzdHJlYW0iLCJkb21haW4iOiJhLmV4YW1wbGUuY29tIiwiY2VydCI6Ii0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJQmtUQ0IuLi5cbi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0ifSwiYmFja2VuZCI6eyJ0eXBlIjoic2hhZG93c29ja3MiLCJtZXRob2QiOiJhZXMtMjU2LWdjbSIsInBhc3N3b3JkIjoic2VjcmV0In19"
	if _, err := ray2sing.DnstSingbox(specExample); err == nil || !strings.Contains(err.Error(), "slipstream") {
		t.Fatalf("slipstream: %v", err)
	}
	if _, err := ray2sing.Ray2SingboxOptions(context.Background(), specExample, false); err == nil {
		t.Fatal("slipstream converted")
	}
}

func TestDnstErrors(t *testing.T) {
	for name, link := range map[string]string{
		"path":      "dnst://t.example.com/dnstt?pubkey=" + dnstPubKey,
		"transport": "dnst://t.example.com/iodine/socks?pubkey=" + dnstPubKey,
		"backend":   "dnst://t.example.com/dnstt/vmess?pubkey=" + dnstPubKey,
		"ssh user":  "dnst://t.example.com/dnstt/ssh?pubkey=" + dnstPubKey + "&password=x",
		"ss method": "dnst://t.example.com/dnstt/shadowsocks?pubkey=" + dnstPubKey + "&password=x",
		"json":      "dnst://bm90LWpzb24",
	} {
		if _, err := ray2sing.DnstSingbox(link); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
