package ray2sing

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// A dnst:// link is the dnst URL (github.com/net2share/dnst-url-spec, v1.0): one shareable link
// for a DNS tunnel and the service behind it.
//
//	dnst://<domain>/<transport>/<backend>?<params>#<tag>
//	dnst://<base64url JSON {"tag","transport":{...},"backend":{...}}>
//
// The transport (dnstt, vaydns or masterdns) becomes a dnstt or masterdns outbound and the
// backend the outbound in front of it, as the chain "front -> tunnel", so that the existing link
// parsers build both. slipstream is not supported. Parameters the spec does not know, such as
// the dnstt resolvers, pass through to the tunnel outbound. The spec names no resolvers: dnstt,
// vaydns and masterdns use the built-in list ("auto"), masterdns through its smart pool.

// defaultMasterdnsResolvers are used for a masterdns link without resolvers and smart pool.
var defaultMasterdnsResolvers = []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"}

// dnstTransportParams are the transport parameters of the spec; the rest of the query goes to
// the tunnel link as well, for extensions such as resolvers.
var dnstBackendParams = map[string]bool{"user": true, "password": true, "pk": true, "method": true}

type dnstLink struct {
	transport string
	backend   string
	domain    string
	tag       string
	params    map[string]string // normalized keys (normalizeStr)
}

func parseDnstLink(link string) (*dnstLink, error) {
	if !strings.HasPrefix(strings.ToLower(link), "dnst://") {
		return nil, fmt.Errorf("not a dnst:// link")
	}
	body := strings.TrimSpace(link[len("dnst://"):])
	if !strings.Contains(body, "/") {
		return parseDnstJSON(body)
	}
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("dnst link: %w", err)
	}
	path := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(path) != 2 || path[0] == "" || path[1] == "" {
		return nil, fmt.Errorf("dnst link: the path must be /<transport>/<backend>, got %q", u.Path)
	}
	d := &dnstLink{
		transport: strings.ToLower(path[0]),
		backend:   strings.ToLower(path[1]),
		domain:    u.Hostname(),
		tag:       u.Fragment,
		params:    make(map[string]string),
	}
	for key, values := range u.Query() {
		d.params[normalizeStr(key)] = strings.Join(values, ",")
	}
	// cert and pk are base64url of the PEM body in this form
	if pk, ok := d.params["pk"]; ok && pk != "" && !strings.Contains(pk, "-----BEGIN") {
		pem, err := dnstKeyBodyToPEM(pk)
		if err != nil {
			return nil, fmt.Errorf("dnst link: pk: %w", err)
		}
		d.params["pk"] = pem
	}
	return d, nil
}

func parseDnstJSON(body string) (*dnstLink, error) {
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(body, "="))
	if err != nil {
		if decoded, err2 := decodeBase64FaultTolerant(body); err2 == nil {
			raw = []byte(decoded)
		} else {
			return nil, fmt.Errorf("dnst link: not base64url JSON: %w", err)
		}
	}
	var doc struct {
		Tag       string                     `json:"tag"`
		Transport map[string]json.RawMessage `json:"transport"`
		Backend   map[string]json.RawMessage `json:"backend"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("dnst link: invalid JSON: %w", err)
	}
	if doc.Transport == nil || doc.Backend == nil {
		return nil, fmt.Errorf("dnst link: the JSON needs \"transport\" and \"backend\" objects")
	}
	d := &dnstLink{tag: doc.Tag, params: make(map[string]string)}
	for key, value := range doc.Transport {
		s := jsonRawString(value)
		switch normalizeStr(key) {
		case "type":
			d.transport = strings.ToLower(s)
		case "domain":
			d.domain = s
		default:
			d.params[normalizeStr(key)] = s
		}
	}
	for key, value := range doc.Backend {
		s := jsonRawString(value)
		if normalizeStr(key) == "type" {
			d.backend = strings.ToLower(s)
			continue
		}
		d.params[normalizeStr(key)] = s
	}
	return d, nil
}

func jsonRawString(raw json.RawMessage) string {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return strings.Trim(string(raw), `"`)
	}
	return jsonValueString(value)
}

// dnstKeyBodyToPEM turns the base64url body of a private key into the PEM the SSH outbound reads,
// with the header that matches the key's format (OpenSSH, PKCS#8, PKCS#1 or SEC1).
func dnstKeyBodyToPEM(body string) (string, error) {
	body = strings.TrimRight(strings.TrimSpace(body), "=")
	der, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		der, err = base64.RawStdEncoding.DecodeString(body)
		if err != nil {
			return "", fmt.Errorf("not base64url")
		}
	}
	var kind string
	switch {
	case strings.HasPrefix(string(der), "openssh-key-v1\x00"):
		kind = "OPENSSH PRIVATE KEY"
	default:
		if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			kind = "PRIVATE KEY"
		} else if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
			kind = "RSA PRIVATE KEY"
		} else if _, err := x509.ParseECPrivateKey(der); err == nil {
			kind = "EC PRIVATE KEY"
		} else {
			return "", fmt.Errorf("not an OpenSSH, PKCS#8, PKCS#1 or EC private key")
		}
	}
	std := base64.StdEncoding.EncodeToString(der)
	var lines []string
	for len(std) > 64 {
		lines = append(lines, std[:64])
		std = std[64:]
	}
	lines = append(lines, std)
	return "-----BEGIN " + kind + "-----\n" + strings.Join(lines, "\n") + "\n-----END " + kind + "-----\n", nil
}

// chain writes the links the dnst link stands for, joined with " -> ".
func (d *dnstLink) chain() (string, error) {
	if d.domain == "" {
		return "", fmt.Errorf("dnst link: the tunnel domain is missing")
	}
	var tunnel string
	switch d.transport {
	case "dnstt", "vaydns":
		tunnel = d.dnsttLink()
	case "masterdns":
		link, err := d.masterdnsLink()
		if err != nil {
			return "", err
		}
		tunnel = link
	case "slipstream":
		return "", fmt.Errorf("dnst link %q: the slipstream transport is not supported", d.tag)
	case "":
		return "", fmt.Errorf("dnst link: the transport is missing")
	default:
		return "", fmt.Errorf("dnst link %q: unknown transport %q (dnstt, vaydns and masterdns are supported)", d.tag, d.transport)
	}

	user := d.params["user"]
	password := d.params["password"]
	var front *url.URL
	switch d.backend {
	case "socks":
		if d.transport == "masterdns" {
			// the MasterDnsVPN server connects to the destination itself; a SOCKS user and
			// password are set on the server, not sent by the client
			return tunnel, nil
		}
		front = &url.URL{Scheme: "socks", Host: "127.0.0.1:1080"}
		if user != "" {
			front.User = url.UserPassword(user, password)
		}
	case "ssh":
		if user == "" {
			return "", fmt.Errorf("dnst link %q: the SSH user is missing", d.tag)
		}
		front = &url.URL{Scheme: "ssh", Host: "127.0.0.1:22"}
		if password != "" {
			front.User = url.UserPassword(user, password)
		} else {
			front.User = url.User(user)
		}
		if pk := d.params["pk"]; pk != "" {
			front.RawQuery = url.Values{"pk": {pk}}.Encode()
		}
	case "shadowsocks":
		method := d.params["method"]
		if method == "" || password == "" {
			return "", fmt.Errorf("dnst link %q: the Shadowsocks method and password are required", d.tag)
		}
		front = &url.URL{Scheme: "ss", Host: "127.0.0.1:8388", User: url.UserPassword(method, password)}
	case "custom":
		// the service behind the tunnel is given by another link, chained after this one
		return tunnel, nil
	case "":
		return "", fmt.Errorf("dnst link: the backend is missing")
	default:
		return "", fmt.Errorf("dnst link %q: unknown backend %q (socks, ssh, shadowsocks and custom are supported)", d.tag, d.backend)
	}
	front.Fragment = d.tag
	return front.String() + " -> " + tunnel, nil
}

// dnsttLink writes the dnstt outbound link: the spec's transport parameters, and every other
// parameter that is not a backend one (resolvers, utls, max-qname-len, ...).
func (d *dnstLink) dnsttLink() string {
	query := url.Values{}
	for key, value := range d.params {
		if dnstBackendParams[key] || key == "type" || key == "domain" {
			continue
		}
		query.Set(key, value)
	}
	query.Set("domain", d.domain)
	if _, set := d.params["dnsttcompat"]; !set {
		// original DNSTT: its wire format; VayDNS: its own unless the link says otherwise
		query.Set("dnstt-compat", boolParam(d.transport == "dnstt"))
	}
	if _, set := d.params["resolver"]; !set {
		if r, set := d.params["resolvers"]; set {
			query.Del("resolvers")
			query.Set("resolver", r)
		} else {
			query.Set("resolver", "auto")
		}
	}
	u := url.URL{Scheme: "dnstt", Host: d.domain, RawQuery: query.Encode(), Fragment: d.tag}
	return u.String()
}

// masterdnsLink writes the masterdns outbound link: mkey and encryption from the spec, the mode
// from the backend (socks: the server connects; anything else: its TCP forwarding). Resolvers the
// link leaves out are chosen by the masterdns link (see MasterdnsSingbox).
func (d *dnstLink) masterdnsLink() (string, error) {
	key := getOneOfN(d.params, "", "mkey", "key")
	encryption := d.params["encryption"]
	if key == "" && encryption != "0" && !strings.EqualFold(encryption, "none") {
		return "", fmt.Errorf("dnst link %q: mkey (the MasterDnsVPN encryption key) is missing", d.tag)
	}
	query := url.Values{}
	for key, value := range d.params {
		if dnstBackendParams[key] || key == "type" || key == "domain" || key == "mkey" || key == "key" {
			continue
		}
		query.Set(key, value)
	}
	if key != "" {
		query.Set("key", key)
	}
	if d.backend != "socks" {
		query.Set("mode", "tcp")
	}
	u := url.URL{Scheme: "masterdns", Host: d.domain, RawQuery: query.Encode(), Fragment: d.tag}
	return u.String(), nil
}

// expandDnstLink turns a dnst:// link into its chain of links. A link that cannot be converted
// is left as it is, so DnstSingbox reports why.
func expandDnstLink(config string) string {
	if !strings.HasPrefix(strings.ToLower(config), "dnst://") {
		return config
	}
	d, err := parseDnstLink(config)
	if err != nil {
		return config
	}
	chain, err := d.chain()
	if err != nil {
		return config
	}
	return chain
}

// DnstSingbox is reached for a dnst:// link that expandDnstLink could not convert; it reports why.
func DnstSingbox(link string) (*T.Outbound, error) {
	d, err := parseDnstLink(link)
	if err != nil {
		return nil, err
	}
	if _, err := d.chain(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("dnst link %q is read as a chain of links", d.tag)
}
