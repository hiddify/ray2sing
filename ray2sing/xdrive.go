package ray2sing

import (
	"encoding/json"

	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	sjson "github.com/sagernet/sing/common/json"
)

// xdriveLinkSettings is Xray's xdriveSettings, carried as JSON in the xdrive= parameter of a link
// with type=xdrive (Xray has no share link form for XDRIVE). address and port are Xray's
// streamSettings address and port: the fronting address of the storage requests.
type xdriveLinkSettings struct {
	RemoteFolder      string          `json:"remoteFolder"`
	Service           string          `json:"service"`
	Secrets           []string        `json:"secrets"`
	SegmentBytes      uint32          `json:"segmentBytes"`
	FlushIntervalMs   uint32          `json:"flushIntervalMs"`
	PollIntervalMs    uint32          `json:"pollIntervalMs"`
	MaxPollIntervalMs uint32          `json:"maxPollIntervalMs"`
	SessionTTLSeconds uint32          `json:"sessionTtlSeconds"`
	Concurrency       uint32          `json:"concurrency"`
	EagerWindowMs     uint32          `json:"eagerWindowMs"`
	HoleTimeoutMs     uint32          `json:"holeTimeoutMs"`
	Template          json.RawMessage `json:"template"`
	S3                *struct {
		Endpoint  string `json:"endpoint"`
		Region    string `json:"region"`
		Bucket    string `json:"bucket"`
		PathStyle *bool  `json:"pathStyle"`
	} `json:"s3"`
	Xmux *struct {
		MaxConcurrency   Xbadoption.Range `json:"maxConcurrency"`
		MaxConnections   Xbadoption.Range `json:"maxConnections"`
		CMaxReuseTimes   Xbadoption.Range `json:"cMaxReuseTimes"`
		HMaxRequestTimes Xbadoption.Range `json:"hMaxRequestTimes"`
		HMaxReusableSecs Xbadoption.Range `json:"hMaxReusableSecs"`
		HKeepAlivePeriod int64            `json:"hKeepAlivePeriod"`
	} `json:"xmux"`
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

func getXDriveTransport(decoded map[string]string) (*option.V2RayTransportOptions, error) {
	content := decoded["xdrive"]
	if content == "" {
		return nil, E.New("xdrive: missing the xdrive parameter")
	}
	var settings xdriveLinkSettings
	if err := json.Unmarshal([]byte(content), &settings); err != nil {
		return nil, E.Cause(err, "xdrive: parse the xdrive parameter")
	}
	options := option.V2RayXDriveOptions{
		Service:           settings.Service,
		RemoteFolder:      settings.RemoteFolder,
		Secrets:           settings.Secrets,
		SegmentBytes:      settings.SegmentBytes,
		FlushIntervalMs:   settings.FlushIntervalMs,
		PollIntervalMs:    settings.PollIntervalMs,
		MaxPollIntervalMs: settings.MaxPollIntervalMs,
		SessionTTLSeconds: settings.SessionTTLSeconds,
		Concurrency:       settings.Concurrency,
		EagerWindowMs:     settings.EagerWindowMs,
		HoleTimeoutMs:     settings.HoleTimeoutMs,
		Template:          sjson.RawMessage(settings.Template),
		FrontingAddress:   settings.Address,
		FrontingPort:      settings.Port,
	}
	if settings.S3 != nil {
		options.S3 = &option.V2RayXDriveS3Options{
			Endpoint:  settings.S3.Endpoint,
			Region:    settings.S3.Region,
			Bucket:    settings.S3.Bucket,
			PathStyle: settings.S3.PathStyle,
		}
	}
	if settings.Xmux != nil {
		options.Xmux = &option.V2RayXHTTPXmuxOptions{
			MaxConcurrency:   settings.Xmux.MaxConcurrency,
			MaxConnections:   settings.Xmux.MaxConnections,
			CMaxReuseTimes:   settings.Xmux.CMaxReuseTimes,
			HMaxRequestTimes: settings.Xmux.HMaxRequestTimes,
			HMaxReusableSecs: settings.Xmux.HMaxReusableSecs,
			HKeepAlivePeriod: settings.Xmux.HKeepAlivePeriod,
		}
	}
	return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeXDrive, XDriveOptions: options}, nil
}
