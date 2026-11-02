package ray2sing

import (
	"net/url"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// ipv6Hint reads a link's `ipv6` parameter: `ipv6=1` (true, yes, on) declares that the proxy's exit
// carries IPv6, `ipv6=0` (false, no, off) that it does not. The core takes a declaration as known
// from the start (no verification to wait for), until the proxy's own connections say otherwise.
// Nothing is declared without the parameter, or for a link that is not a URL (a vmess:// blob).
func ipv6Hint(link string) (carried bool, declared bool) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Scheme == "" {
		return false, false
	}
	switch strings.ToLower(parsed.Query().Get("ipv6")) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	}
	return false, false
}

// declareIPv6 puts the links' IPv6 declarations where the core's monitoring reads them,
// experimental.monitoring.ipv6_declared, by the outbound's final tag.
func declareIPv6(options *T.Options, declared map[string]bool) {
	if len(declared) == 0 {
		return
	}
	if options.Experimental == nil {
		options.Experimental = &T.ExperimentalOptions{}
	}
	if options.Experimental.Monitoring == nil {
		options.Experimental.Monitoring = &T.MonitoringOptions{}
	}
	options.Experimental.Monitoring.IPv6Declared = declared
}
