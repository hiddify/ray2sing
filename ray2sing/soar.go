package ray2sing

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	soaroutbound "github.com/sagernet/sing-box/protocol/hiddify/soar"
)

// SoarSingbox reads a soar:// link into a soar outbound (a Soar client,
// github.com/getlantern/soar). Soar defines no link of its own; two forms are read:
//
//	soar://<base64url of a WhiteDNS profile JSON>
//	soar://t.example.com?pk=<server public key>&resolvers=8.8.8.8,1.1.1.1&country=ir#name
//	soar://<server public key in base64url>@t.example.com?resolvers=8.8.8.8#name
//
// The first is the profile WhiteDNS exports and imports (schema "whitedns.profile": the server's
// domain and public_key, its resolvers and soarSettings). In the URL form the query keys are the
// soar outbound's fields (resolvers, smart_pool, tcp, safe_qname, max_qname, max_answer, hold,
// max_inflight, max_path_window, max_streams, ...) and the discovery ones of smart_pool
// (country, sample_ranges, discovery_want, discovery_concurrency, discovery_pace); a standard
// base64 key in the query is percent-encoded, or written in base64url.
//
// Resolvers left out, or "auto", turn on Soar's own resolver discovery. The resolvers written
// go through the outbound's smart pool unless smart_pool=0.
func SoarSingbox(link string) (*T.Outbound, error) {
	if params, name, ok := whiteDNSProfileLink(link, "soar://"); ok {
		return soarOutbound(params, name)
	}
	u, err := ParseUrl(link, 53)
	if err != nil {
		return nil, err
	}
	params := u.Params
	if u.Hostname != "" && getOneOfN(params, "", "domain", "zone") == "" {
		params["domain"] = u.Hostname
	}
	if u.Username != "" && soarKeyParam(params) == "" {
		params["publickey"] = u.Username
	}
	return soarOutbound(params, u.Name)
}

func soarKeyParam(params map[string]string) string {
	return getOneOfN(params, "", "public_key", "pk", "pubkey", "publickey", "server_key", "key")
}

func soarOutbound(params map[string]string, name string) (*T.Outbound, error) {
	domain := strings.TrimSuffix(getOneOfN(params, "", "domain", "zone"), ".")
	if domain == "" {
		return nil, fmt.Errorf("soar link: the tunnel domain is missing")
	}
	// a "+" of a standard base64 key in a query arrives as a space
	key := strings.ReplaceAll(strings.TrimSpace(soarKeyParam(params)), " ", "+")
	if _, err := soaroutbound.ParsePublicKey(key); err != nil {
		return nil, fmt.Errorf("soar link: %w", err)
	}
	options := &T.SoarOptions{
		DialerOptions:     getDialerOptions(params),
		Domain:            domain,
		PublicKey:         key,
		Resolvers:         splitMasterdnsList(getOneOfN(params, "", "resolvers", "resolver", "dns")),
		SmartPool:         soarSmartPoolOption(getOneOfN(params, "", "smart_pool", "smart-pool")),
		PreTestDomain:     getOneOfN(params, "", "pretest_domain"),
		PreTestRecordType: getOneOfN(params, "", "pretest_record_type"),
		TCP:               strings.ToLower(getOneOfN(params, "", "tcp", "transport")),
		SafeQName:         toInt(getOneOfN(params, "", "safe_qname")),
		MaxQName:          toInt(getOneOfN(params, "", "max_qname")),
		MaxAnswer:         toInt(getOneOfN(params, "", "max_answer")),
		Hold:              durationOrSeconds(getOneOfN(params, "", "hold")),
		MaxInflight:       toInt(getOneOfN(params, "", "max_inflight")),
		MaxPathWindow:     toInt(getOneOfN(params, "", "max_path_window")),
		MaxStreams:        toInt(getOneOfN(params, "", "max_streams")),
		StreamWindow:      toInt(getOneOfN(params, "", "stream_window")),
		SendBuffer:        toInt(getOneOfN(params, "", "send_buffer")),
		SessionIdle:       durationOrSeconds(getOneOfN(params, "", "session_idle")),
		ConnectTimeout:    durationOrSeconds(getOneOfN(params, "", "connect_timeout")),
	}
	options.SmartPool = withDiscovery(options.SmartPool, params, true)
	if toBool(getOneOfN(params, "", "discovery"), false) && len(options.Resolvers) > 0 {
		options.Resolvers = append(options.Resolvers, "auto")
	}
	if name == "" {
		name = "soar"
	}
	return &T.Outbound{
		Type:    C.TypeSoar,
		Tag:     name,
		Options: options,
	}, nil
}

// discoveryOption reads the resolver discovery parameters shared by the DNS tunnel links
// (country, sample_ranges, discovery_want, discovery_concurrency, discovery_pace); nil when the
// link sets none.
func discoveryOption(params map[string]string) *T.ResolverDiscoveryOptions {
	discovery := &T.ResolverDiscoveryOptions{
		Country:      strings.ToLower(getOneOfN(params, "", "country", "cc")),
		SampleRanges: toInt(getOneOfN(params, "", "sample_ranges")),
		Want:         toInt(getOneOfN(params, "", "discovery_want")),
		Concurrency:  toInt(getOneOfN(params, "", "discovery_concurrency")),
		Pace:         durationOrSeconds(getOneOfN(params, "", "discovery_pace")),
	}
	if *discovery == (T.ResolverDiscoveryOptions{}) {
		return nil
	}
	return discovery
}

// withDiscovery puts the link's discovery parameters into its smart_pool block, making one with
// the pool's default state (enabled) when the link has none.
func withDiscovery(pool *T.SmartPoolOptions, params map[string]string, enabled bool) *T.SmartPoolOptions {
	discovery := discoveryOption(params)
	if discovery == nil {
		return pool
	}
	if pool == nil {
		pool = &T.SmartPoolOptions{Enabled: enabled}
	}
	pool.Discovery = discovery
	return pool
}

// soarSmartPoolOption reads smart_pool for an outbound whose pool is on by default: empty keeps
// the default (nil), 0/false turns it off, 1/true is the pool with its defaults, anything else is
// the pool's load balance strategy.
func soarSmartPoolOption(value string) *T.SmartPoolOptions {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if enabled := toBoolN(value); enabled != nil {
		return &T.SmartPoolOptions{Enabled: *enabled}
	}
	return &T.SmartPoolOptions{Enabled: true, LoadBalance: value}
}

// whiteDNSProfileLink reads the profile link of WhiteDNS: scheme://<base64url JSON> with schema
// "whitedns.profile". It returns the profile as parameters keyed like the URL form (normalized
// keys): name, domain, the key (public_key for Soar, key and encryption for MasterDnsVPN),
// resolvers, and the Soar settings with WhiteDNS's defaults.
func whiteDNSProfileLink(link, scheme string) (map[string]string, string, bool) {
	if !strings.HasPrefix(strings.ToLower(link), scheme) {
		return nil, "", false
	}
	body := link[len(scheme):]
	name := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		name, _ = url.PathUnescape(body[i+1:])
		body = body[:i]
	}
	if i := strings.IndexByte(body, '?'); i >= 0 {
		body = body[:i]
	}
	body = strings.TrimSpace(body)
	if body == "" || strings.ContainsAny(body, "@.:") {
		return nil, "", false
	}
	decoded, err := decodeBase64FaultTolerant(body)
	if err != nil {
		return nil, "", false
	}
	var root struct {
		Schema  string `json:"schema"`
		Profile struct {
			Name   string `json:"name"`
			Server struct {
				Domain           string `json:"domain"`
				PublicKey        string `json:"public_key"`
				EncryptionKey    string `json:"encryption_key"`
				EncryptionMethod *int   `json:"encryption_method"`
			} `json:"server"`
			Resolvers    []string                   `json:"resolvers"`
			SoarSettings map[string]json.RawMessage `json:"soarSettings"`
		} `json:"profile"`
	}
	if err := json.Unmarshal([]byte(decoded), &root); err != nil || root.Schema != "whitedns.profile" {
		return nil, "", false
	}
	profile := root.Profile
	params := map[string]string{
		"domain": strings.TrimSuffix(strings.TrimSpace(profile.Server.Domain), "."),
	}
	if profile.Server.PublicKey != "" {
		params["publickey"] = profile.Server.PublicKey
	}
	if profile.Server.EncryptionKey != "" {
		params["key"] = profile.Server.EncryptionKey
	}
	if profile.Server.EncryptionMethod != nil {
		params["encryption"] = strconv.Itoa(*profile.Server.EncryptionMethod)
	}
	if len(profile.Resolvers) > 0 {
		params["resolvers"] = strings.Join(profile.Resolvers, ",")
	}
	if scheme == "soar://" {
		whiteDNSSoarSettings(params, profile.SoarSettings)
	}
	if name == "" {
		name = profile.Name
	}
	return params, name, true
}

// whiteDNSSoarSettings maps WhiteDNS's soarSettings onto the soar outbound's parameters. Without
// the block WhiteDNS's defaults apply: discovery on, for Iran.
func whiteDNSSoarSettings(params map[string]string, settings map[string]json.RawMessage) {
	str := func(key string) (string, bool) {
		raw, ok := settings[key]
		if !ok {
			return "", false
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s, true
		}
		return strings.Trim(string(raw), `"`), true
	}
	set := func(param, key string, scale func(string) string) {
		if value, ok := str(key); ok && value != "" {
			if scale != nil {
				value = scale(value)
			}
			params[param] = value
		}
	}
	unit := func(d time.Duration) func(string) string {
		return func(v string) string {
			n, err := strconv.Atoi(v)
			if err != nil {
				return ""
			}
			return (time.Duration(n) * d).String()
		}
	}
	kib := func(v string) string {
		n, err := strconv.Atoi(v)
		if err != nil {
			return ""
		}
		return strconv.Itoa(n * 1024)
	}

	discovery, country := "true", "ir"
	if settings != nil {
		discovery, _ = str("discovery")
		country, _ = str("country") // "" for GLOBAL
	}
	params["discovery"] = discovery
	if !toBool(discovery, false) && params["resolvers"] == "" {
		params["resolvers"] = "1.1.1.1" // WhiteDNS's resolver for a profile without any
	}
	if country = strings.ToLower(strings.TrimSpace(country)); len(country) == 2 {
		params["country"] = country
	}
	set("tcp", "transport", nil)
	set("discoverywant", "discoveryWant", nil)
	set("discoveryconcurrency", "discoveryConcurrency", nil)
	set("discoverypace", "discoveryPaceMs", unit(time.Millisecond))
	set("safeqname", "safeQName", nil)
	set("maxqname", "maxQName", nil)
	set("maxanswer", "maxAnswer", nil)
	set("hold", "holdMs", unit(time.Millisecond))
	set("maxinflight", "maxInflight", nil)
	set("maxpathwindow", "maxPathWindow", nil)
	set("maxstreams", "maxStreams", nil)
	set("streamwindow", "streamWindowKiB", kib)
	set("sendbuffer", "sendBufferKiB", kib)
	set("sessionidle", "sessionIdleSeconds", unit(time.Second))
	set("connecttimeout", "dialTimeoutSeconds", unit(time.Second))
}
