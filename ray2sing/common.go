package ray2sing

import (
	"encoding/base64"
	"net"
	"net/url"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"strings"
	"time"
)

type ParserFunc func(string) (*option.Outbound, error)

func getTLSOptions(decoded map[string]string) *option.OutboundTLSOptions {
	if !(decoded["tls"] == "tls" || decoded["security"] == "tls" || decoded["security"] == "reality") {
		return nil
	}

	serverName := decoded["sni"]
	if serverName == "" {
		serverName = decoded["add"]
	}

	var ECHOpts *option.OutboundECHOptions
	valECH, hasECH := decoded["ech"]
	if hasECH && (valECH != "0") {
		ECHOpts = &option.OutboundECHOptions{
			Enabled: true,
		}
	}

	fp := decoded["fp"]
	if fp == "" {
		fp = "chrome"
	}

	tlsOptions := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   decoded["insecure"] == "true",
		DisableSNI: serverName == "",
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fp,
		},
		ECH:       ECHOpts,
		TLSTricks: getTricksOptions(decoded),
	}

	if alpn, ok := decoded["alpn"]; ok && alpn != "" {
		tlsOptions.ALPN = strings.Split(alpn, ",")
	}

	return tlsOptions
}

func getTricksOptions(decoded map[string]string) *option.TLSTricksOptions {
	trick := option.TLSTricksOptions{}
	if decoded["mc"] == "1" {
		trick.MixedCaseSNI = true
	}
	trick.PaddingMode = decoded["padmode"]
	trick.PaddingSNI = decoded["padsni"]
	trick.PaddingSize = decoded["padsize"]

	if !trick.MixedCaseSNI && trick.PaddingMode == "" && trick.PaddingSNI == "" && trick.PaddingSize == "" {
		return nil
	}
	return &trick
}
func getFragmentOptions(decoded map[string]string) *option.TLSFragmentOptions {
	trick := option.TLSFragmentOptions{}
	trick.Size = decoded["fgsize"]
	trick.Sleep = decoded["fgsleep"]

	if trick.Size != "" {
		trick.Enabled = true
	}
	if !trick.Enabled {
		return nil
	}
	return &trick
}
func getMuxOptions(decoded map[string]string) *option.OutboundMultiplexOptions {
	mux := option.OutboundMultiplexOptions{}
	mux.Protocol = decoded["mux"]
	if mux.Protocol == "" {
		return nil
	}
	mux.Enabled = true
	mux.MaxConnections = toInt(decoded["mux_max"])
	mux.MinStreams = toInt(decoded["mux_min"])
	mux.Padding = decoded["mux_pad"] == "true"

	if decoded["mux_up"] != "" && decoded["mux_down"] != "" {
		mux.Brutal = &option.BrutalOptions{
			Enabled:  true,
			UpMbps:   toInt(decoded["mux_up"]),
			DownMbps: toInt(decoded["mux_down"]),
		}
	}
	return &mux
}
func getTransportOptions(decoded map[string]string) (*option.V2RayTransportOptions, error) {
	var transportOptions option.V2RayTransportOptions
	host, net, path := decoded["host"], decoded["net"], decoded["path"]
	if net == "" {
		net = decoded["type"]
	}
	if path == "" {
		path = decoded["serviceName"]
	}
	// fmoption.Printf("\n\nheaderType:%s, net:%s, type:%s\n\n", decoded["headerType"], net, decoded["type"])
	if (decoded["type"] == "http" || decoded["headerType"] == "http") && net == "tcp" {
		net = "http"
	}

	switch net {
	case "tcp":
		return nil, nil
	case "http":
		transportOptions.Type = C.V2RayTransportTypeHTTP
		if decoded["security"] != "tls" {
			transportOptions.HTTPOptions.Method = "GET"
		}
		if host != "" {
			transportOptions.HTTPOptions.Host = option.Listable[string]{host}
		}
		httpPath := path
		if httpPath == "" {
			httpPath = "/"
		}
		transportOptions.HTTPOptions.Path = httpPath
	case "ws":
		transportOptions.Type = C.V2RayTransportTypeWebsocket
		if host != "" {
			transportOptions.WebsocketOptions.Headers = map[string]option.Listable[string]{"Host": {host}}
		}
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			pathURL, err := url.Parse(path)
			if err != nil {
				return &option.V2RayTransportOptions{}, err
			}
			pathQuery := pathURL.Query()
			transportOptions.WebsocketOptions.MaxEarlyData = 0
			transportOptions.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			maxEarlyDataString := pathQuery.Get("ed")
			if maxEarlyDataString != "" {
				maxEarlyDate, err := strconv.ParseUint(maxEarlyDataString, 10, 32)
				if err == nil {
					transportOptions.WebsocketOptions.MaxEarlyData = uint32(maxEarlyDate)
					pathQuery.Del("ed")
					pathURL.RawQuery = pathQuery.Encode()
				}
			}
			transportOptions.WebsocketOptions.Path = pathURL.String()
		}
	case "grpc":
		transportOptions.Type = C.V2RayTransportTypeGRPC
		transportOptions.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName:         path,
			IdleTimeout:         option.Duration(15 * time.Second),
			PingTimeout:         option.Duration(15 * time.Second),
			PermitWithoutStream: false,
		}
	case "quic":
		transportOptions.Type = C.V2RayTransportTypeQUIC
	default:
		return nil, E.New("unknown transport type: " + net)
	}

	return &transportOptions, nil
}
func getDialerOptions(decoded map[string]string) option.DialerOptions {
	return T.DialerOptions{
		TLSFragment: getFragmentOptions(decoded),
	}
}

func decodeBase64IfNeeded(b64string string) (string, error) {
	padding := len(b64string) % 4
	b64stringFix := b64string
	if padding != 0 {
		b64stringFix += string("===="[:4-padding])
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(b64stringFix)
	if err != nil {
		return b64string, err
	}

	return string(decodedBytes), nil
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func toInt16(s string) uint16 {
	val, err := strconv.ParseInt(s, 10, 17)
	if err != nil {
		// fmoption.Printf("err %v", err)
		// handle the error appropriately; here we return 0
		return 443
	}
	return uint16(val)
}

func isIPOnly(s string) bool {
	return net.ParseIP(s) != nil
}
