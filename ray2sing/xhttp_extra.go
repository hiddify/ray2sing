package ray2sing

import (
	"github.com/sagernet/sing-box/option"
)

type XHTTPExtra struct {
	option.V2RayXHTTPBaseOptions
	DownloadSettings *DownloadSettings `json:"downloadSettings,omitempty"`
}

type DownloadSettings struct {
	option.V2RayXHTTPBaseOptions
	Address         string         `json:"address,omitempty"`
	Port            int            `json:"port,omitempty"`
	Security        string         `json:"security,omitempty"`
	TLSSettings     *TLSConfig     `json:"tlsSettings"`
	REALITYSettings *REALITYConfig `json:"realitySettings"`
}

type TLSConfig struct {
	Insecure bool `json:"allowInsecure"`
	// Certs                   []*TLSCertConfig `json:"certificates"`
	ServerName string   `json:"serverName"`
	ALPN       []string `json:"alpn"`
	// EnableSessionResumption bool     `json:"enableSessionResumption"`
	// DisableSystemRoot       bool             `json:"disableSystemRoot"`
	// MinVersion string `json:"minVersion"`
	// MaxVersion string `json:"maxVersion"`
	// CipherSuites            string           `json:"cipherSuites"`
	Fingerprint      string `json:"fingerprint"`
	RejectUnknownSNI bool   `json:"rejectUnknownSni"`
	// PinnedPeerCertSha256    string           `json:"pinnedPeerCertSha256"`
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
	ServerName  string `json:"serverName"`
	// Password      string `json:"password"`
	PublicKey string `json:"publicKey"`
	ShortId   string `json:"shortId"`
	// Mldsa65Verify string `json:"mldsa65Verify"`
	// SpiderX       string `json:"spiderX"`
}
