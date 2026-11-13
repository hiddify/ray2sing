package ray2sing

import (
	"math"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"time"
)

// xrayQuicParams is the part of Xray's finalmask quicParams that the sing-box hysteria2
// outbound has an option for.
type xrayQuicParams struct {
	Congestion              string           `json:"congestion"`
	BbrProfile              string           `json:"bbrProfile"`
	BrutalUp                sjson.RawMessage `json:"brutalUp"`
	BrutalDown              sjson.RawMessage `json:"brutalDown"`
	MaxIdleTimeout          int64            `json:"maxIdleTimeout"`
	KeepAlivePeriod         int64            `json:"keepAlivePeriod"`
	DisablePathMTUDiscovery bool             `json:"disablePathMTUDiscovery"`
	DisableChromeParrot     bool             `json:"disableChromeParrot"`
}

type xrayHysteriaFinalMask struct {
	UDP        []T.FinalMaskItem `json:"udp"`
	QuicParams *xrayQuicParams   `json:"quicParams"`
}

// applyHysteria2FinalMask reads the Xray finalmask (fm=) of a hysteria2 link.
//
// Xray's hysteria has no obfs of its own: salamander is a udp finalmask, and Xray links carry it
// both in fm and in the standard obfs= parameter. The fm mask is applied on the dialer socket
// (see applyFinalMask), so the outbound's own obfs is dropped, or salamander would run twice.
//
// quicParams is not a mask: its congestion and QUIC settings become hysteria2 options.
func applyHysteria2FinalMask(link string, opts *T.Hysteria2OutboundOptions) error {
	content, err := finalMaskParam(link)
	if err != nil || strings.TrimSpace(content) == "" {
		return nil // applyFinalMask reports a bad fm
	}
	var fm xrayHysteriaFinalMask
	if err := sjson.Unmarshal([]byte(content), &fm); err != nil {
		return nil
	}
	for _, mask := range fm.UDP {
		if strings.EqualFold(mask.Type, "salamander") {
			opts.Obfs = nil
			break
		}
	}
	q := fm.QuicParams
	if q == nil {
		return nil
	}
	up, err := xrayBandwidthMbps(q.BrutalUp)
	if err != nil {
		return E.Cause(err, "fm quicParams brutalUp")
	}
	down, err := xrayBandwidthMbps(q.BrutalDown)
	if err != nil {
		return E.Cause(err, "fm quicParams brutalDown")
	}
	switch strings.ToLower(q.Congestion) {
	case "", "brutal", "force-brutal":
		// sing-box sends with Brutal at min(up, server rx) when up is set, BBR otherwise
		opts.UpMbps = up
	case "bbr", "reno":
		// BBR: no up, so sing-box does not pick Brutal (it has no Reno)
	default:
		return E.New("fm quicParams: unknown congestion ", q.Congestion)
	}
	opts.DownMbps = down
	if profile := strings.ToLower(q.BbrProfile); profile != "" {
		opts.BBRProfile = profile
	}
	if q.MaxIdleTimeout > 0 {
		opts.IdleTimeout = badoption.Duration(time.Duration(q.MaxIdleTimeout) * time.Second)
	}
	if q.KeepAlivePeriod > 0 {
		opts.KeepAlivePeriod = badoption.Duration(time.Duration(q.KeepAlivePeriod) * time.Second)
	}
	opts.DisablePathMTUDiscovery = opts.DisablePathMTUDiscovery || q.DisablePathMTUDiscovery
	opts.DisableChromeParrot = opts.DisableChromeParrot || q.DisableChromeParrot
	return nil
}

// xrayBandwidthMbps converts an Xray Bandwidth ("100 mbps", "1g", a number of bytes per second)
// to sing-box Mbps. Xray's units are bits in powers of 1024, divided by 8 to bytes per second.
func xrayBandwidthMbps(raw sjson.RawMessage) (int, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return 0, nil
	}
	if unquoted, err := strconv.Unquote(s); err == nil {
		s = unquoted
	}
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, nil
	}
	idx := len(s)
	for i, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			idx = i
			break
		}
	}
	val, err := strconv.ParseFloat(s[:idx], 64)
	if err != nil {
		return 0, err
	}
	mul := 1.0
	switch strings.TrimSpace(s[idx:]) {
	case "", "b", "bps":
	case "k", "kb", "kbps":
		mul = 1 << 10
	case "m", "mb", "mbps":
		mul = 1 << 20
	case "g", "gb", "gbps":
		mul = 1 << 30
	case "t", "tb", "tbps":
		mul = 1 << 40
	default:
		return 0, E.New("unsupported unit: ", s[idx:])
	}
	bytesPerSecond := val * mul / 8
	if bytesPerSecond <= 0 {
		return 0, nil
	}
	// sing-box: 1 Mbps = 125000 bytes per second
	return max(1, int(math.Round(bytesPerSecond/125000))), nil
}
