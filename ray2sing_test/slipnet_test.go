package ray2sing_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

// slipnetLink builds a SlipNet profile link (version 18, fields separated by "|") with the given
// field values by position.
func slipnetLink(values map[int]string) string {
	fields := make([]string, 70)
	fields[0] = "18"
	for i, v := range values {
		fields[i] = v
	}
	return "slipnet://" + base64.StdEncoding.EncodeToString([]byte(strings.Join(fields, "|")))
}

const slipnetPubKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func slipnetDNSFields(tunnelType string) map[int]string {
	return map[int]string{1: tunnelType, 2: "Slip Test", 3: "t.example.com", 4: "8.8.8.8:53:0,1.1.1.1:5353:0", 11: slipnetPubKey, 12: "socksuser", 13: "p@ss:word"}
}

func parseSlipnet(t *testing.T, link string) (front T.Outbound, tunnel T.Outbound) {
	t.Helper()
	options, err := ray2sing.Ray2SingboxOptions(context.Background(), link, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Outbounds) != 2 {
		t.Fatalf("outbounds: %+v", options.Outbounds)
	}
	// the chain is written from the inside out: the dnstt outbound comes first
	tunnel, front = options.Outbounds[0], options.Outbounds[1]
	if tunnel.Type != C.TypeDNSTT || !strings.Contains(tunnel.Tag, "§hide§") {
		t.Fatalf("tunnel: %s %s", tunnel.Type, tunnel.Tag)
	}
	if !strings.HasPrefix(front.Tag, "Slip Test") || strings.Contains(front.Tag, "§hide§") {
		t.Fatalf("front: %s %s", front.Type, front.Tag)
	}
	return front, tunnel
}

// A DNSTT profile is a socks outbound (the SlipNet server forwards to a SOCKS server) through a
// dnstt outbound in the original DNSTT wire format.
func TestSlipnetDnsttProfile(t *testing.T) {
	front, tunnel := parseSlipnet(t, slipnetLink(slipnetDNSFields("dnstt")))
	socks := front.Options.(*T.SOCKSOutboundOptions)
	if front.Type != C.TypeSOCKS || socks.Username != "socksuser" || socks.Password != "p@ss:word" || socks.Detour != tunnel.Tag {
		t.Fatalf("front: %s %+v", front.Tag, socks)
	}
	dnstt := tunnel.Options.(*T.DnsttOptions)
	if dnstt.Domain != "t.example.com" || dnstt.PublicKey != slipnetPubKey || !dnstt.DnsttCompat || dnstt.MaxQnameLen != nil || (dnstt.MTU != nil && *dnstt.MTU != 0) {
		t.Fatalf("dnstt: %+v", dnstt)
	}
	if strings.Join(dnstt.Resolvers, " ") != "8.8.8.8:53 1.1.1.1:5353" {
		t.Fatalf("resolvers: %v", dnstt.Resolvers)
	}
}

// A NoizDNS profile ("sayedns") keeps the short names; DoT and DoH transports and the payload size
// are carried over; an SSH variant puts an ssh outbound in front.
func TestSlipnetNoizdnsSSHProfile(t *testing.T) {
	fields := slipnetDNSFields("sayedns_ssh")
	fields[14], fields[15], fields[16], fields[17], fields[19] = "1", "root", "s3cret", "2222", "1.2.3.4"
	fields[22] = "tls"
	fields[39] = "600"
	front, tunnel := parseSlipnet(t, slipnetLink(fields))
	ssh := front.Options.(*T.SSHOutboundOptions)
	if front.Type != C.TypeSSH || ssh.User != "root" || ssh.Password != "s3cret" || ssh.ServerPort != 2222 || ssh.Server != "127.0.0.1" || ssh.Detour != tunnel.Tag {
		t.Fatalf("front: %+v", ssh)
	}
	dnstt := tunnel.Options.(*T.DnsttOptions)
	if !dnstt.DnsttCompat || dnstt.MaxQnameLen == nil || *dnstt.MaxQnameLen != 150 || dnstt.MTU == nil || *dnstt.MTU != 600 {
		t.Fatalf("dnstt: %+v", dnstt)
	}
	if strings.Join(dnstt.Resolvers, " ") != "dot://8.8.8.8:853 dot://1.1.1.1:5353" {
		t.Fatalf("resolvers: %v", dnstt.Resolvers)
	}

	fields[22], fields[21] = "https", "https://dns.google/dns-query"
	_, tunnel = parseSlipnet(t, slipnetLink(fields))
	if r := tunnel.Options.(*T.DnsttOptions).Resolvers; len(r) != 1 || r[0] != "https://dns.google/dns-query" {
		t.Fatalf("doh resolvers: %v", r)
	}
}

// A VayDNS profile carries its wire format fields.
func TestSlipnetVaydnsProfile(t *testing.T) {
	fields := slipnetDNSFields("vaydns")
	fields[41], fields[42], fields[43], fields[44], fields[48], fields[49] = "0", "cname", "120", "15.5", "4", "4"
	_, tunnel := parseSlipnet(t, slipnetLink(fields))
	dnstt := tunnel.Options.(*T.DnsttOptions)
	if dnstt.DnsttCompat || dnstt.RecordType != "cname" || *dnstt.MaxQnameLen != 120 || *dnstt.RPS != 15.5 || *dnstt.MaxNumLabels != 4 || *dnstt.ClientIDSize != 4 {
		t.Fatalf("dnstt: %+v", dnstt)
	}
	fields[41] = "1"
	_, tunnel = parseSlipnet(t, slipnetLink(fields))
	if !tunnel.Options.(*T.DnsttOptions).DnsttCompat {
		t.Fatal("dnstt-compat not carried")
	}
}

// A standalone SSH profile is one ssh outbound; unsupported and locked profiles are refused with
// a reason.
func TestSlipnetOtherProfiles(t *testing.T) {
	fields := map[int]string{1: "ssh", 2: "Just SSH", 14: "1", 15: "u", 16: "p", 17: "22", 19: "ssh.example.com"}
	options, err := ray2sing.Ray2SingboxOptions(context.Background(), slipnetLink(fields), false)
	if err != nil || len(options.Outbounds) != 1 || options.Outbounds[0].Type != C.TypeSSH {
		t.Fatalf("%v %+v", err, options)
	}
	ssh := options.Outbounds[0].Options.(*T.SSHOutboundOptions)
	if ssh.Server != "ssh.example.com" || ssh.User != "u" {
		t.Fatalf("ssh: %+v", ssh)
	}

	for name, link := range map[string]string{
		"slipstream": slipnetLink(map[int]string{1: "ss", 2: "x", 3: "t.example.com", 11: slipnetPubKey}),
		"no pubkey":  slipnetLink(map[int]string{1: "dnstt", 2: "x", 3: "t.example.com"}),
		"locked":     "slipnet-enc://" + base64.StdEncoding.EncodeToString([]byte("18|dnstt|x")),
		"short":      "slipnet://" + base64.StdEncoding.EncodeToString([]byte("18|dnstt")),
	} {
		if _, err := ray2sing.SlipnetSingbox(link); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := ray2sing.Ray2SingboxOptions(context.Background(), link, false); err == nil {
			t.Errorf("%s: converted", name)
		}
	}
}
