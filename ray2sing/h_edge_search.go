package ray2sing

import (
	"encoding/json"
	"strings"

	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// edgeSearchOptions reads the search parameters a warp:// or psiphon:// link shares:
// search_timeout (3m; a Go duration or seconds; deep, -1 or unlimited for a deep search without a
// limit, and a value above 3m is a deep search with that limit), deep_concurrency,
// block_bits_ipv4 (24) and block_bits_ipv6 (48).
func edgeSearchOptions(param func(keys ...string) string) T.EdgeSearchOptions {
	timeout := param("search_timeout")
	var searchTimeout badoption.Duration
	switch strings.ToLower(timeout) {
	case "deep", "unlimited", "none", "inf", "infinite":
		searchTimeout = badoption.Duration(-1)
	default:
		searchTimeout = warpDuration(timeout)
	}
	return T.EdgeSearchOptions{
		SearchTimeout:   searchTimeout,
		DeepConcurrency: toInt(param("deep_concurrency")),
		BlockBitsIPv4:   toInt(param("block_bits_ipv4", "block_bits_v4")),
		BlockBitsIPv6:   toInt(param("block_bits_ipv6", "block_bits_v6")),
	}
}

// psiphonScanner reads the CDN edge scanner of a psiphon:// link: scanner (on unless 0 or false;
// it runs only when Psiphon is the first hop), scan_sets, scan_cidrs, scan_sni, scan_candidates,
// scan_count, scan_concurrency, scan_timeout, max_rtt, and the search parameters. Nil when the
// link sets none, for the outbound's defaults.
func psiphonScanner(params map[string]string) *T.PsiphonScannerOptions {
	param := func(keys ...string) string { return getOneOfN(params, "", keys...) }
	keys := []string{"scanner", "scan", "scan_sets", "scan_cidrs", "scan_sni", "scan_candidates", "scan_count", "scan_concurrency", "scan_timeout", "max_rtt",
		"search_timeout", "deep_concurrency", "block_bits_ipv4", "block_bits_v4", "block_bits_ipv6", "block_bits_v6"}
	set := false
	for _, key := range keys {
		if _, ok := params[normalizeStr(key)]; ok {
			set = true
			break
		}
	}
	if !set {
		return nil
	}
	scanner := &T.PsiphonScannerOptions{
		Sets:              splitList(param("scan_sets")),
		ServerNames:       splitList(param("scan_sni")),
		Candidates:        toInt(param("scan_candidates")),
		Count:             toInt(param("scan_count")),
		Concurrency:       toInt(param("scan_concurrency")),
		Timeout:           warpDuration(param("scan_timeout")),
		MaxRTT:            warpDuration(param("max_rtt", "scan_max_rtt")),
		EdgeSearchOptions: edgeSearchOptions(param),
	}
	if value := param("scanner", "scan"); value != "" {
		enabled := toBool(value, true)
		scanner.Enabled = &enabled
	}
	if cidrs := param("scan_cidrs"); cidrs != "" {
		_ = json.Unmarshal(jsonStringList(cidrs), &scanner.CIDRs)
	}
	return scanner
}
