package ray2sing

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// OpenVPN profiles: a .ovpn file as it is, or an ovpn:// link to one. The link is
//
//	ovpn://<the .ovpn file in base64>?user=<username>&pass=<password>#<name>
//
// user and pass are for a profile that asks for them (auth-user-pass) without carrying them
// inline. Both become an openvpn-client endpoint; the certificates and keys must be inline
// (<ca>, <cert>, <key>, <tls-auth>, <tls-crypt>, <tls-crypt-v2>, <secret>), as a link or a
// pasted file has no files beside it.

// ovpnDirective matches a line that only an OpenVPN profile has.
var ovpnDirective = regexp.MustCompile(`(?m)^[ \t]*(remote[ \t]+\S|<ca>|<tls-crypt|<tls-auth|dev[ \t]+tun|dev[ \t]+tap|auth-user-pass\b|remote-cert-tls\b)`)

// isOpenVPNProfile reports whether text is a .ovpn file: a remote, and one more of its own lines.
func isOpenVPNProfile(text string) bool {
	if strings.Contains(text, "://") && !strings.Contains(text, "<ca>") {
		return false
	}
	matches := ovpnDirective.FindAllString(text, -1)
	hasRemote := false
	for _, m := range matches {
		if strings.HasPrefix(strings.TrimSpace(m), "remote") && !strings.HasPrefix(strings.TrimSpace(m), "remote-cert-tls") {
			hasRemote = true
		}
	}
	return hasRemote && len(matches) >= 2
}

// OpenVPNSingbox reads an ovpn:// link.
func OpenVPNSingbox(link string) (*T.Endpoint, error) {
	rest := strings.TrimPrefix(link, "ovpn://")
	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	var query url.Values
	if i := strings.Index(rest, "?"); i >= 0 {
		query, _ = url.ParseQuery(rest[i+1:])
		rest = rest[:i]
	}
	payload, err := url.PathUnescape(rest)
	if err != nil {
		payload = rest
	}
	profile, err := decodeBase64FaultTolerant(strings.TrimSpace(payload))
	if err != nil {
		return nil, fmt.Errorf("ovpn link: the profile is not base64: %w", err)
	}
	username := query.Get("user")
	if username == "" {
		username = query.Get("username")
	}
	password := query.Get("pass")
	if password == "" {
		password = query.Get("password")
	}
	return ParseOVPN(string(profile), name, username, password)
}

// ParseOVPN reads a .ovpn profile into an openvpn-client endpoint, named name, or else after its
// first server; username and password are used when the profile has none inline.
func ParseOVPN(profile, name, username, password string) (*T.Endpoint, error) {
	opts := &T.OpenVPNClientEndpointOptions{}
	tls := &T.OpenVPNOutboundTLSOptions{}
	blocks := map[string][]string{}
	var (
		remotes       []T.OpenVPNRemoteOptions
		port          uint16 = 1194
		proto         string
		tlsAuthDir    string
		secretDir     string
		keyDirection  string
		cipher        string
		authUserPass  bool
		inBlock       string
		blockLines    []string
		hasSecret     bool
		controlWrap   string
		hasDataCipher bool
	)
	for _, rawLine := range strings.Split(strings.ReplaceAll(profile, "\r", ""), "\n") {
		line := strings.TrimSpace(rawLine)
		if inBlock != "" {
			if strings.EqualFold(line, "</"+inBlock+">") {
				blocks[inBlock] = blockLines
				inBlock, blockLines = "", nil
			} else if line != "" {
				blockLines = append(blockLines, line)
			}
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			inBlock = strings.ToLower(strings.Trim(line, "<>"))
			continue
		}
		args := ovpnFields(line)
		directive := strings.ToLower(strings.TrimPrefix(args[0], "--"))
		args = args[1:]
		arg := func(i int) string {
			if i < len(args) {
				return args[i]
			}
			return ""
		}
		switch directive {
		case "remote":
			remote := T.OpenVPNRemoteOptions{}
			remote.Server = arg(0)
			if p, err := strconv.Atoi(arg(1)); err == nil {
				remote.ServerPort = uint16(p)
			}
			remote.Network = ovpnNetwork(arg(2))
			remotes = append(remotes, remote)
		case "port", "rport":
			if p, err := strconv.Atoi(arg(0)); err == nil {
				port = uint16(p)
			}
		case "proto":
			proto = ovpnNetwork(arg(0))
		case "remote-random":
			opts.RemoteRandom = true
		case "dev":
			if strings.HasPrefix(arg(0), "tap") {
				return nil, fmt.Errorf("ovpn: a tap device (layer 2) is not supported, only tun")
			}
		case "dev-type":
			if arg(0) == "tap" {
				return nil, fmt.Errorf("ovpn: a tap device (layer 2) is not supported, only tun")
			}
		case "topology":
			opts.Topology = arg(0)
		case "cipher":
			cipher = arg(0)
		case "data-ciphers", "ncp-ciphers":
			hasDataCipher = true
			for _, c := range strings.Split(arg(0), ":") {
				if c = strings.TrimSpace(c); c != "" {
					opts.DataCiphers = append(opts.DataCiphers, c)
				}
			}
		case "data-ciphers-fallback":
			opts.DataCiphersFallback = arg(0)
		case "auth":
			opts.Auth = arg(0)
		case "tls-auth": // tls-auth [file] [direction]
			controlWrap = "tls_auth"
			tlsAuthDir = ovpnLastDirection(args)
		case "tls-crypt":
			controlWrap = "tls_crypt"
		case "tls-crypt-v2":
			controlWrap = "tls_crypt_v2"
		case "key-direction":
			keyDirection = arg(0)
		case "secret": // secret [file] [direction]
			hasSecret = true
			secretDir = ovpnLastDirection(args)
		case "remote-cert-tls":
			tls.RemoteCertificateTLS = arg(0)
		case "ns-cert-type":
			tls.NSCertificateType = arg(0)
		case "verify-x509-name":
			tls.ServerName = arg(0)
			switch arg(1) {
			case "name", "name-prefix", "subject":
				tls.ServerNameType = arg(1)
			}
		case "tls-version-min":
			tls.VersionMin = arg(0)
		case "tls-version-max":
			tls.VersionMax = arg(0)
		case "tls-cert-profile":
			tls.CertificateProfile = arg(0)
		case "comp-lzo":
			switch arg(0) {
			case "", "adaptive":
				opts.CompressionLZO = "adaptive"
			default:
				opts.CompressionLZO = arg(0)
			}
		case "compress":
			if arg(0) == "" {
				opts.Compression = "stub"
			} else {
				opts.Compression = arg(0)
			}
		case "allow-compression":
			opts.AllowCompression = arg(0)
		case "tun-mtu":
			if v, err := strconv.Atoi(arg(0)); err == nil {
				opts.MTU = uint32(v)
			}
		case "mssfix":
			if arg(0) == "0" {
				opts.MSSFixDisabled = true
			} else if v, err := strconv.Atoi(arg(0)); err == nil {
				opts.MSSFix = uint32(v)
			}
		case "fragment":
			if v, err := strconv.Atoi(arg(0)); err == nil {
				opts.Fragment = uint32(v)
			}
		case "ping":
			opts.PingInterval = ovpnSeconds(arg(0))
		case "ping-restart":
			opts.PingRestart = ovpnSeconds(arg(0))
		case "keepalive":
			opts.PingInterval = ovpnSeconds(arg(0))
			opts.PingRestart = ovpnSeconds(arg(1))
		case "reneg-sec":
			if arg(0) == "0" {
				opts.RenegotiateDisabled = true
			} else {
				opts.RenegotiateInterval = ovpnSeconds(arg(0))
			}
		case "hand-window":
			opts.HandshakeWindow = ovpnSeconds(arg(0))
		case "route-nopull":
			opts.RouteNoPull = true
		case "redirect-gateway":
			opts.RedirectGateway = true
			opts.RedirectGatewayFlags = append(opts.RedirectGatewayFlags, args...)
		case "block-ipv6":
			opts.BlockIPv6 = true
		case "pull-filter":
			if len(args) >= 2 {
				opts.PullFilters = append(opts.PullFilters, T.OpenVPNPullFilterOptions{Action: arg(0), Text: arg(1)})
			}
		case "explicit-exit-notify":
			n := 1
			if v, err := strconv.Atoi(arg(0)); err == nil {
				n = v
			}
			opts.ExplicitExitNotify = uint32(n)
		case "auth-user-pass":
			authUserPass = true
		case "auth-retry":
			opts.AuthRetry = arg(0)
		case "static-challenge":
			opts.StaticChallenge = arg(0)
			opts.StaticChallengeEcho = arg(1) == "1"
		}
	}

	if len(remotes) == 0 {
		return nil, fmt.Errorf("ovpn: no remote server")
	}
	for i := range remotes {
		if remotes[i].ServerPort == 0 {
			remotes[i].ServerPort = port
		}
		if remotes[i].Network == "" {
			remotes[i].Network = proto
		}
	}
	if len(remotes) == 1 {
		opts.Server, opts.ServerPort, opts.Network = remotes[0].Server, remotes[0].ServerPort, remotes[0].Network
	} else {
		opts.Servers = remotes
		opts.Network = proto
	}

	// the credentials: inline, else those given beside the profile
	if lines := blocks["auth-user-pass"]; len(lines) > 0 {
		opts.Username = lines[0]
		if len(lines) > 1 {
			opts.Password = lines[1]
		}
	}
	if opts.Username == "" && authUserPass {
		opts.Username, opts.Password = username, password
	}

	if hasSecret || len(blocks["secret"]) > 0 {
		// a static key, no TLS
		opts.Mode = "static_key"
		opts.StaticKey = blocks["secret"]
		opts.KeyDirection = ovpnDirection(firstNonEmpty(secretDir, keyDirection))
		opts.Cipher = cipher
	} else {
		opts.Mode = "tls"
		if cipher != "" && opts.DataCiphersFallback == "" {
			// in TLS mode, cipher is what a server that does not negotiate uses
			opts.DataCiphersFallback = cipher
			if !hasDataCipher {
				opts.DataCiphers = append(opts.DataCiphers, cipher)
			}
		}
		tls.Certificate = blocks["ca"]
		tls.ClientCertificate = blocks["cert"]
		tls.ClientKey = blocks["key"]
		if len(tls.Certificate) == 0 {
			return nil, fmt.Errorf("ovpn: no inline <ca> certificate")
		}
		for _, wrap := range []struct{ kind, block string }{{"tls_crypt_v2", "tls-crypt-v2"}, {"tls_crypt", "tls-crypt"}, {"tls_auth", "tls-auth"}} {
			if key := blocks[wrap.block]; len(key) > 0 && (controlWrap == "" || controlWrap == wrap.kind) {
				control := &T.OpenVPNControlWrapOptions{Type: wrap.kind, Key: key}
				if wrap.kind == "tls_auth" {
					control.Direction = ovpnDirection(firstNonEmpty(tlsAuthDir, keyDirection))
				}
				tls.ControlWrap = control
				break
			}
		}
		opts.TLS = tls
	}

	if name == "" {
		name = remotes[0].Server
	}
	return &T.Endpoint{Type: C.TypeOpenVPNClient, Tag: name, Options: opts}, nil
}

// ovpnFields splits a directive into its words, a quoted one whole.
func ovpnFields(line string) []string {
	var fields []string
	var current strings.Builder
	quoted, has := false, false
	for _, r := range line {
		switch {
		case r == '"':
			quoted, has = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if has {
				fields = append(fields, current.String())
				current.Reset()
				has = false
			}
		default:
			current.WriteRune(r)
			has = true
		}
	}
	if has {
		fields = append(fields, current.String())
	}
	return fields
}

// ovpnNetwork is the endpoint's network for a proto: udp, tcp (tcp-client), udp4, tcp6...
func ovpnNetwork(proto string) string {
	proto = strings.TrimSuffix(strings.ToLower(proto), "-client")
	switch proto {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
		return proto
	}
	return ""
}

// ovpnLastDirection is the direction a directive ends with ("tls-auth ta.key 1"), if any.
func ovpnLastDirection(args []string) string {
	if n := len(args); n > 0 && (args[n-1] == "0" || args[n-1] == "1") {
		return args[n-1]
	}
	return ""
}

// ovpnDirection is the endpoint's key direction for OpenVPN's: 0 the server's, 1 the client's.
func ovpnDirection(direction string) string {
	switch direction {
	case "0":
		return "server"
	case "1":
		return "client"
	}
	return ""
}

func ovpnSeconds(value string) badoption.Duration {
	seconds, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return badoption.Duration(time.Duration(seconds) * time.Second)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
