package ray2sing

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// A slipnet:// link is a SlipNet profile: base64 of fields separated by "|" (the app's export
// format, version 18). The DNS tunnel types become a dnstt outbound with the outbound the SlipNet
// server forwards to in front of it, as the chain "front -> dnstt://...", so that the existing
// link parsers build both:
//
//   - dnstt and sayedns (NoizDNS): the original DNSTT wire format; the NoizDNS server reads it,
//     and NoizDNS's shorter names are kept. Its stealth label splitting and cover traffic are
//     client-side only and are not reproduced.
//   - vaydns: the VayDNS wire format with the profile's record type, name length, rate and
//     client id size.
//   - the _ssh variants: an ssh outbound through the tunnel; the others a socks outbound with the
//     profile's SOCKS user and password.
//
// A standalone ssh profile becomes an ssh:// link. slipnet-enc:// (locked) profiles, Slipstream,
// NaiveProxy, Tor, DoH and VLESS profiles are not read.

// slipnetProfile holds the fields of a profile this converter uses.
type slipnetProfile struct {
	tunnelType   string
	name         string
	domain       string
	resolvers    string // "8.8.8.8:53:0,1.1.1.1:53:0"
	publicKey    string
	socksUser    string
	socksPass    string
	sshUser      string
	sshPass      string
	sshPort      int
	sshHost      string
	dnsTransport string // udp, tcp, tls (DoT), https (DoH)
	dohURL       string
	payloadSize  int // KCP MTU, 0 = full

	vaydnsDnsttCompat  bool
	vaydnsRecordType   string
	vaydnsMaxQnameLen  int
	vaydnsRps          float64
	vaydnsMaxNumLabels int
	vaydnsClientIDSize int

	sshTLS, sshWS bool
	sshHTTPProxy  string
}

func parseSlipnetProfile(link string) (*slipnetProfile, error) {
	lower := strings.ToLower(link)
	if strings.HasPrefix(lower, "slipnet-enc://") {
		return nil, fmt.Errorf("slipnet-enc:// locked profiles are not supported, export the profile as a plain slipnet:// link")
	}
	if !strings.HasPrefix(lower, "slipnet://") {
		return nil, fmt.Errorf("not a slipnet:// link")
	}
	body := strings.Join(strings.Fields(link[len("slipnet://"):]), "")
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	decoded, err := decodeBase64FaultTolerant(body)
	if err != nil {
		return nil, fmt.Errorf("slipnet link: %w", err)
	}
	fields := strings.Split(decoded, "|")
	if len(fields) < 12 {
		return nil, fmt.Errorf("slipnet link: %d fields, at least 12 needed", len(fields))
	}
	field := func(i int) string {
		if i < len(fields) {
			return fields[i]
		}
		return ""
	}
	intField := func(i int) int {
		v, _ := strconv.Atoi(field(i))
		return v
	}
	p := &slipnetProfile{
		tunnelType:   strings.ToLower(field(1)),
		name:         field(2),
		domain:       field(3),
		resolvers:    field(4),
		publicKey:    field(11),
		socksUser:    field(12),
		socksPass:    field(13),
		dohURL:       field(21),
		dnsTransport: strings.ToLower(field(22)),
		payloadSize:  intField(39),
	}
	if len(fields) > 19 {
		p.sshUser = field(15)
		p.sshPass = field(16)
		p.sshPort = intField(17)
		if p.sshPort <= 0 {
			p.sshPort = 22
		}
		p.sshHost = field(19)
	}
	if len(fields) > 49 {
		p.vaydnsDnsttCompat = field(41) == "1"
		p.vaydnsRecordType = field(42)
		p.vaydnsMaxQnameLen = intField(43)
		p.vaydnsRps, _ = strconv.ParseFloat(field(44), 64)
		p.vaydnsMaxNumLabels = intField(48)
		p.vaydnsClientIDSize = intField(49)
	}
	if len(fields) > 59 {
		p.sshTLS = field(50) == "1"
		p.sshHTTPProxy = field(52)
		p.sshWS = field(55) == "1"
	}
	return p, nil
}

// dnsttResolvers writes the profile's resolvers for the dnstt outbound, in the profile's DNS
// transport: plain UDP "host:port", DoT "dot://host:port" or DoH "https://...".
func (p *slipnetProfile) dnsttResolvers() []string {
	var resolvers []string
	for _, entry := range strings.Split(p.resolvers, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ":")
		host := parts[0]
		if host == "" {
			continue
		}
		port := "53"
		if len(parts) >= 2 && parts[1] != "" {
			port = parts[1]
		}
		switch p.dnsTransport {
		case "https", "doh":
			if p.dohURL != "" {
				return []string{p.dohURL}
			}
			resolvers = append(resolvers, "https://"+host+"/dns-query")
		case "tls", "dot":
			if port == "53" {
				port = "853"
			}
			resolvers = append(resolvers, "dot://"+net.JoinHostPort(host, port))
		default: // udp; tcp DNS is not supported, plain UDP is used
			resolvers = append(resolvers, net.JoinHostPort(host, port))
		}
	}
	if len(resolvers) == 0 {
		resolvers = []string{"auto"}
	}
	return resolvers
}

// chain writes the links the profile stands for, joined with " -> " (the first goes through the
// second).
func (p *slipnetProfile) chain() (string, error) {
	sshMode := strings.HasSuffix(p.tunnelType, "_ssh")
	base := strings.TrimSuffix(p.tunnelType, "_ssh")
	switch base {
	case "dnstt", "sayedns", "vaydns", "":
	case "ssh", "direct":
		if p.sshTLS || p.sshWS || p.sshHTTPProxy != "" {
			return "", fmt.Errorf("slipnet profile %q: SSH over TLS, WebSocket or an HTTP proxy is not supported", p.name)
		}
		if p.sshHost == "" {
			return "", fmt.Errorf("slipnet profile %q: the SSH server address is missing", p.name)
		}
		return p.sshLink(p.sshHost, p.sshPort), nil
	default:
		return "", fmt.Errorf("slipnet profile %q: tunnel type %q is not supported (DNSTT, NoizDNS, VayDNS and SSH are)", p.name, p.tunnelType)
	}
	if p.publicKey == "" {
		return "", fmt.Errorf("slipnet profile %q: the server's public key is missing", p.name)
	}
	if p.domain == "" {
		return "", fmt.Errorf("slipnet profile %q: the tunnel domain is missing", p.name)
	}

	query := url.Values{}
	query.Set("domain", p.domain)
	query.Set("pubkey", p.publicKey)
	query.Set("resolver", strings.Join(p.dnsttResolvers(), ","))
	switch base {
	case "vaydns":
		query.Set("dnstt-compat", boolParam(p.vaydnsDnsttCompat))
		if p.vaydnsRecordType != "" {
			query.Set("record-type", p.vaydnsRecordType)
		}
		if p.vaydnsMaxQnameLen > 0 {
			query.Set("max-qname-len", strconv.Itoa(p.vaydnsMaxQnameLen))
		}
		if p.vaydnsRps > 0 {
			query.Set("rps", strconv.FormatFloat(p.vaydnsRps, 'f', -1, 64))
		}
		if p.vaydnsMaxNumLabels > 0 {
			query.Set("max-num-labels", strconv.Itoa(p.vaydnsMaxNumLabels))
		}
		if p.vaydnsClientIDSize > 0 {
			query.Set("clientid-size", strconv.Itoa(p.vaydnsClientIDSize))
		}
	case "sayedns":
		query.Set("dnstt-compat", "1")
		query.Set("max-qname-len", "150") // NoizDNS keeps names short
	default:
		query.Set("dnstt-compat", "1")
	}
	if p.payloadSize > 0 {
		query.Set("mtu", strconv.Itoa(p.payloadSize))
	}
	tunnel := url.URL{Scheme: "dnstt", Host: p.domain, RawQuery: query.Encode(), Fragment: p.name}

	var front string
	if sshMode {
		user, pass := p.sshUser, p.sshPass
		if user == "" {
			user, pass = p.socksUser, p.socksPass
		}
		if user == "" {
			return "", fmt.Errorf("slipnet profile %q: the SSH user is missing", p.name)
		}
		front = p.sshLinkWith(user, pass, "127.0.0.1", p.sshPort)
	} else {
		socks := url.URL{Scheme: "socks", Host: "127.0.0.1:1080", Fragment: p.name}
		if p.socksUser != "" {
			socks.User = url.UserPassword(p.socksUser, p.socksPass)
		}
		front = socks.String()
	}
	return front + " -> " + tunnel.String(), nil
}

func (p *slipnetProfile) sshLink(host string, port int) string {
	user, pass := p.sshUser, p.sshPass
	if user == "" {
		user, pass = p.socksUser, p.socksPass
	}
	return p.sshLinkWith(user, pass, host, port)
}

func (p *slipnetProfile) sshLinkWith(user, pass, host string, port int) string {
	u := url.URL{Scheme: "ssh", Host: net.JoinHostPort(host, strconv.Itoa(port)), Fragment: p.name}
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return u.String()
}

func boolParam(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// expandLinks rewrites links that stand for a chain of outbounds into the " -> " chain form.
func expandLinks(config string) string {
	return expandDnstLink(expandSlipnetLink(expandInnerLinks(expandAetherLink(config))))
}

// expandSlipnetLink turns a slipnet:// profile into its chain of links. A profile that cannot be
// converted is left as it is, so SlipnetSingbox reports why.
func expandSlipnetLink(config string) string {
	if !strings.HasPrefix(strings.ToLower(config), "slipnet://") {
		return config
	}
	profile, err := parseSlipnetProfile(config)
	if err != nil {
		return config
	}
	chain, err := profile.chain()
	if err != nil {
		return config
	}
	return chain
}

// SlipnetSingbox is reached for a slipnet:// link that expandSlipnetLink could not convert, and
// for slipnet-enc:// links; it reports why.
func SlipnetSingbox(link string) (*T.Outbound, error) {
	profile, err := parseSlipnetProfile(link)
	if err != nil {
		return nil, err
	}
	if _, err := profile.chain(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("slipnet profile %q stands for several outbounds and is read as a chain", profile.name)
}
