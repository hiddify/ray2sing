package ray2sing

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/sagernet/sing-box/option"
)

// The structs below take snake_case keys: xrayExtraToSnake converts the camelCase keys that Xray
// writes in an XHTTP extra (xPaddingKey, scMaxEachPostBytes, noGRPCHeader, downloadSettings, ...)
// to the snake_case keys of the sing-box options (x_padding_key, sc_max_each_post_bytes,
// no_grpc_header, download_settings, ...). encoding/json matches keys without regard to case but
// not to underscores, so before this only one-word keys (path, host, headers) were read.

// xrayExtraToSnake returns extra with every object key in snake_case, except the header names
// under "headers", which are kept as written.
func xrayExtraToSnake(extra []byte) ([]byte, error) {
	var value any
	if err := json.Unmarshal(extra, &value); err != nil {
		return nil, err
	}
	return json.Marshal(snakeKeys(value))
}

func snakeKeys(value any) any {
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, item := range value {
			key = camelToSnake(key)
			if key == "headers" {
				out[key] = item
				continue
			}
			out[key] = snakeKeys(item)
		}
		return out
	case []any:
		for i, item := range value {
			value[i] = snakeKeys(item)
		}
	}
	return value
}

// camelToSnake turns xPaddingKey into x_padding_key, noGRPCHeader into no_grpc_header and
// hMaxRequestTimes into h_max_request_times; a snake_case key is returned unchanged.
func camelToSnake(key string) string {
	runes := []rune(key)
	var out strings.Builder
	for i, r := range runes {
		if unicode.IsUpper(r) {
			previousLower := i > 0 && (unicode.IsLower(runes[i-1]) || unicode.IsDigit(runes[i-1]))
			acronymEnd := i > 0 && unicode.IsUpper(runes[i-1]) && i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if (previousLower || acronymEnd) && runes[i-1] != '_' {
				out.WriteByte('_')
			}
			r = unicode.ToLower(r)
		}
		out.WriteRune(r)
	}
	return out.String()
}

type XHTTPExtra struct {
	option.V2RayXHTTPBaseOptions
	DownloadSettings *DownloadSettings `json:"download_settings,omitempty"`
}

type DownloadSettings struct {
	option.V2RayXHTTPBaseOptions
	Address         string         `json:"address,omitempty"`
	Port            int            `json:"port,omitempty"`
	Security        string         `json:"security,omitempty"`
	TLSSettings     *TLSConfig     `json:"tls_settings"`
	REALITYSettings *REALITYConfig `json:"reality_settings"`
	// Xray/hiddifypanel nest the download leg's path/host/mode/headers here
	XHTTPSettings *option.V2RayXHTTPBaseOptions `json:"xhttp_settings,omitempty"`
}

type TLSConfig struct {
	Insecure bool `json:"allow_insecure"`
	// Certs                   []*TLSCertConfig `json:"certificates"`
	ServerName string   `json:"server_name"`
	ALPN       []string `json:"alpn"`
	// EnableSessionResumption bool     `json:"enableSessionResumption"`
	// DisableSystemRoot       bool             `json:"disableSystemRoot"`
	// MinVersion string `json:"minVersion"`
	// MaxVersion string `json:"maxVersion"`
	// CipherSuites            string           `json:"cipherSuites"`
	Fingerprint          string `json:"fingerprint"`
	RejectUnknownSNI     bool   `json:"reject_unknown_sni"`
	PinnedPeerCertSha256 string `json:"pinned_peer_cert_sha256"`
	// CurvePreferences        *StringList      `json:"curvePreferences"`
	// MasterKeyLog            string           `json:"masterKeyLog"`
	// ServerNameToVerify      string           `json:"serverNameToVerify"`
	// VerifyPeerCertInNames   []string         `json:"verifyPeerCertInNames"`
	// ECHServerKeys           string           `json:"echServerKeys"`
	// ECHConfigList           string           `json:"echConfigList"`
	// ECHForceQuery           string           `json:"echForceQuery"`
	// ECHSocketSettings       *SocketConfig    `json:"echSockopt"`
}

type REALITYConfig struct {
	// MasterKeyLog string          `json:"masterKeyLog"`
	// Show         bool            `json:"show"`
	// Target       json.RawMessage `json:"target"`
	// Dest         json.RawMessage `json:"dest"`
	// Type         string   `json:"type"`
	// Xver         uint64   `json:"xver"`
	// ServerNames  []string `json:"serverNames"`
	// PrivateKey   string   `json:"privateKey"`
	// MinClientVer string   `json:"minClientVer"`
	// MaxClientVer string   `json:"maxClientVer"`
	// MaxTimeDiff  uint64   `json:"maxTimeDiff"`
	// ShortIds     []string `json:"shortIds"`
	// Mldsa65Seed  string   `json:"mldsa65Seed"`

	// LimitFallbackUpload   LimitFallback `json:"limitFallbackUpload"`
	// LimitFallbackDownload LimitFallback `json:"limitFallbackDownload"`

	Fingerprint string `json:"fingerprint"`
	ServerName  string `json:"server_name"`
	// Password      string `json:"password"`
	PublicKey string `json:"public_key"`
	ShortId   string `json:"short_id"`
	KeyShare  string `json:"key_share"` // Hiddify only, see getRealityKeyShare
	// Mldsa65Verify string `json:"mldsa65Verify"`
	// SpiderX       string `json:"spiderX"`
}
