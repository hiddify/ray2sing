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
	"github.com/sagernet/sing/common/json/badoption"
)

// MasterdnsSingbox reads a masterdns:// link into a masterdns outbound (a MasterDnsVPN client).
// Three forms are read:
//
//	masterdns://v.example.com?key=<key>&resolvers=8.8.8.8,1.1.1.1&encryption=xor#name
//	masterdns://<key>@v.example.com?resolvers=8.8.8.8,1.1.1.1#name
//	masterdns://<base64 of a MasterDnsVPN client JSON config, plus a RESOLVERS list>#name
//
// The query keys are the masterdns outbound's fields (domains, resolvers, encryption, key, mode,
// balancing, packet_duplication, ...). The JSON form uses the keys of client_config.toml
// (DOMAINS, ENCRYPTION_KEY, DATA_ENCRYPTION_METHOD, PROTOCOL_TYPE, RESOLVER_BALANCING_STRATEGY,
// ...), the same document the MasterDnsVPN client takes with -json_base64, with RESOLVERS added
// because the client reads its resolvers from a separate file.
func MasterdnsSingbox(link string) (*T.Outbound, error) {
	if params, name, ok := masterdnsJSONLink(link); ok {
		return masterdnsOutbound(params, name)
	}
	u, err := ParseUrl(link, 53)
	if err != nil {
		return nil, err
	}
	params := u.Params
	if u.Hostname != "" {
		if _, set := params["domains"]; !set {
			if _, set := params["domain"]; !set {
				params["domains"] = u.Hostname
			}
		}
	}
	if u.Username != "" && getOneOfN(params, "", "key", "encryption_key", "password") == "" {
		// the key before "@", with the password part if the key had a ":"
		key := u.Username
		if u.Password != "" {
			key += ":" + u.Password
		}
		params["key"] = key
	}
	return masterdnsOutbound(params, u.Name)
}

// masterdnsJSONLink reads the JSON form of the link: the body is base64 with no "?" or "@" and
// decodes to a JSON object. It returns the object's values as strings keyed like URL parameters.
func masterdnsJSONLink(link string) (map[string]string, string, bool) {
	body := strings.TrimPrefix(link, "masterdns://")
	name := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		name = body[i+1:]
		body = body[:i]
	}
	body = strings.TrimSpace(body)
	if body == "" || strings.ContainsAny(body, "?@:/.") && !strings.HasSuffix(body, "=") && !isBase64CharsOnly(strings.TrimRight(body, "=")) {
		return nil, "", false
	}
	decoded, err := decodeBase64FaultTolerant(body)
	if err != nil {
		return nil, "", false
	}
	decoded = strings.TrimSpace(decoded)
	if !strings.HasPrefix(decoded, "{") {
		return nil, "", false
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, "", false
	}
	params := make(map[string]string, len(doc))
	for key, value := range doc {
		params[normalizeStr(key)] = jsonValueString(value)
	}
	if name == "" {
		name = getOneOfN(params, "", "name", "tag", "remarks")
	} else if unescaped, err := url.PathUnescape(name); err == nil {
		name = unescaped
	}
	return params, name, true
}

func jsonValueString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s := jsonValueString(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(v)
	}
}

// splitList splits a list written with commas, semicolons, whitespace or newlines.
func splitMasterdnsList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// durationOrSeconds reads "2s", "1500ms" or a number of seconds ("2", "1.5", as the MasterDnsVPN
// configuration writes them).
func durationOrSeconds(value string) badoption.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if d, err := time.ParseDuration(value); err == nil {
		return badoption.Duration(d)
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil && seconds > 0 {
		return badoption.Duration(seconds * float64(time.Second))
	}
	return 0
}

func toBoolN(s string) *bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on":
		v := true
		return &v
	case "false", "0", "no", "off":
		v := false
		return &v
	}
	return nil
}

// masterdnsCompressionName turns the configuration's numbers 0 to 3 into names; names pass through.
func masterdnsCompressionName(value string) string {
	switch strings.TrimSpace(value) {
	case "0":
		return "off"
	case "1":
		return "zstd"
	case "2":
		return "lz4"
	case "3":
		return "zlib"
	}
	return value
}

func masterdnsOutbound(params map[string]string, name string) (*T.Outbound, error) {
	domains := splitMasterdnsList(getOneOfN(params, "", "domains", "domain"))
	if len(domains) == 0 {
		return nil, fmt.Errorf("masterdns link: the tunnel domain is missing")
	}
	resolvers := splitMasterdnsList(getOneOfN(params, "", "resolvers", "resolver", "dns"))
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("masterdns link: resolvers are missing (resolvers=8.8.8.8,1.1.1.1)")
	}
	options := &T.MasterDNSOptions{
		DialerOptions:               getDialerOptions(params),
		Domains:                     domains,
		Resolvers:                   resolvers,
		Encryption:                  getOneOfN(params, "", "encryption", "enc", "method", "data_encryption_method"),
		Key:                         getOneOfN(params, "", "key", "encryption_key", "password"),
		Mode:                        strings.ToLower(getOneOfN(params, "", "mode", "protocol_type")),
		Balancing:                   getOneOfN(params, "", "balancing", "balance", "strategy", "resolver_balancing_strategy"),
		PacketDuplication:           toInt(getOneOfN(params, "", "packet_duplication", "dup", "duplication", "packet_duplication_count")),
		SetupPacketDuplication:      toInt(getOneOfN(params, "", "setup_packet_duplication", "setup_dup", "setup_packet_duplication_count")),
		UploadCompression:           masterdnsCompressionName(getOneOfN(params, "", "upload_compression", "ucomp", "upload_compression_type")),
		DownloadCompression:         masterdnsCompressionName(getOneOfN(params, "", "download_compression", "dcomp", "download_compression_type")),
		BaseEncode:                  toBool(getOneOfN(params, "", "base_encode", "base_encode_data"), false),
		MinUploadMTU:                toInt(getOneOfN(params, "", "min_upload_mtu")),
		MaxUploadMTU:                toInt(getOneOfN(params, "", "max_upload_mtu")),
		MinDownloadMTU:              toInt(getOneOfN(params, "", "min_download_mtu")),
		MaxDownloadMTU:              toInt(getOneOfN(params, "", "max_download_mtu")),
		MTUTestTimeout:              durationOrSeconds(getOneOfN(params, "", "mtu_test_timeout")),
		MTUTestRetries:              toInt(getOneOfN(params, "", "mtu_test_retries")),
		MTUTestParallelism:          toInt(getOneOfN(params, "", "mtu_test_parallelism")),
		AutoRemoveLowMTUResolvers:   toBoolN(getOneOfN(params, "", "auto_remove_low_mtu_resolvers", "auto_remove_low_mtu_servers")),
		RecheckInactiveResolvers:    toBoolN(getOneOfN(params, "", "recheck_inactive_resolvers", "recheck_inactive_servers_enabled")),
		AutoDisableTimeoutResolvers: toBoolN(getOneOfN(params, "", "auto_disable_timeout_resolvers", "auto_disable_timeout_servers")),
		Workers:                     toInt(getOneOfN(params, "", "workers", "rx_tx_workers")),
		ProcessWorkers:              toInt(getOneOfN(params, "", "process_workers", "tunnel_process_workers")),
		ARQWindow:                   toInt(getOneOfN(params, "", "arq_window", "arq_window_size")),
		ReadyTimeout:                durationOrSeconds(getOneOfN(params, "", "ready_timeout")),
		ConnectTimeout:              durationOrSeconds(getOneOfN(params, "", "connect_timeout")),
		LogLevel:                    strings.ToLower(getOneOfN(params, "", "log_level")),
	}
	if uot := getOneOfN(params, "", "uot", "udp_over_tcp"); toBool(uot, false) {
		options.UDPOverTCP = &T.UDPOverTCPOptions{Enabled: true}
	}
	if name == "" {
		name = "masterdns"
	}
	return &T.Outbound{
		Type:    C.TypeMasterDNS,
		Tag:     name,
		Options: options,
	}, nil
}
