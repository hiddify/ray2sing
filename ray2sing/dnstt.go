package ray2sing

import (
	"strings"
	"time"

	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// toDurationN reads "60s", "1m" or a number of seconds; nil when empty or invalid.
func toDurationN(s string) *badoption.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		seconds := toInt(s)
		if seconds <= 0 {
			return nil
		}
		d = time.Duration(seconds) * time.Second
	}
	bd := badoption.Duration(d)
	return &bd
}

func DnsttSingbox(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// uot := T.UDPOverTCPOptions{
	// 	Enabled: getOneOfN(decoded, "", "uot") != "false" && getOneOfN(decoded, "", "uot") != "0",
	// }
	d := &T.DnsttOptions{
		DialerOptions: getDialerOptions(decoded),
		PublicKey:     getOneOfN(decoded, "", "pubkey", "publickey", "serverpublickey"),
		Domain:        getOneOfN(decoded, "", "domain", "serveraddress", "address"),
		Resolvers:     strings.Split(getOneOfN(decoded, "", "resolver"), ","),
		// TunnelPerResolver: toInt(getOneOfN(decoded, "1", "tunnelperresolver")),

		PreTestDomain:     getOneOfN(decoded, "", "pretest-domain"),
		PreTestRecordType: getOneOfN(decoded, "", "pretest-record-type"),
		RecordType:        getOneOfN(decoded, "", "record-type"),
		UTLSClientHelloID: getOneOfN(decoded, "", "utls"),

		DnsttCompat:    toBool(getOneOfN(decoded, "false", "dnstt-compat"), false),
		ClientIDSize:   toIntN(getOneOfN(decoded, "", "clientid-size")),
		MaxQnameLen:    toIntN(getOneOfN(decoded, "", "max-qname-len")),
		MaxNumLabels:   toIntN(getOneOfN(decoded, "", "max-num-labels")),
		RPS:            toFloatN(getOneOfN(decoded, "", "rps")),
		SingleResolver: toBool(getOneOfN(decoded, "false", "single-resolver"), false),

		MTU: toIntN(getOneOfN(decoded, "0", "mtu")),

		MaxStreams: toIntN(getOneOfN(decoded, "", "max-streams")),

		IdleTimeout: toDurationN(getOneOfN(decoded, "", "idle-timeout")),
		KeepAlive:   toDurationN(getOneOfN(decoded, "", "keepalive")),
		// OpenStreamTimeout    *badoption.Duration `json:"open-stream-timeout,omitempty"`

		// ReconnectMinDelay    *badoption.Duration `json:"reconnect-min,omitempty"`
		// ReconnectMaxDelay    *badoption.Duration `json:"reconnect-max,omitempty"`
		// SessionCheckInterval *badoption.Duration `json:"session-check-interval,omitempty"`
		// HandshakeTimeout     *badoption.Duration `json:"handshake-timeout,omitempty"`
		// UdpTimeout      *badoption.Duration `json:"udp-timeout,omitempty"`
		UdpAcceptErrors: toBool(getOneOfN(decoded, "false", "udp-accept-errors"), false),
		UdpSharedSocket: toBool(getOneOfN(decoded, "true", "udp-shared-socket"), true),
		UdpWorkers:      toIntN(getOneOfN(decoded, "", "udp-workers")),
		SmartPool:       smartPoolOption(getOneOfN(decoded, "", "smart-pool", "smart_pool")),

		// UDPOverTCP: &uot,
	}

	if d.ClientIDSize == nil && d.RecordType == "" && getOneOfN(decoded, "", "dnstt-compat") == "" {
		d.DnsttCompat = true
	}
	return &T.Outbound{
		Tag:     u.Name + "§hide§",
		Type:    "dnstt",
		Options: d,
	}, nil
}

// smartPoolOption reads smart-pool=1 (the pool with its defaults) or a load balance name
// (roundrobin, weighted, lowest_latency) as the pool's strategy; empty or false means no pool.
func smartPoolOption(value string) *T.SmartPoolOptions {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	switch strings.ToLower(value) {
	case "0", "false", "no", "off":
		return nil
	case "1", "true", "yes", "on":
		return &T.SmartPoolOptions{Enabled: true}
	}
	return &T.SmartPoolOptions{Enabled: true, LoadBalance: value}
}
