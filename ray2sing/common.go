package ray2sing

//based on https://github.com/XTLS/Xray-core/issues/91
//todo merge with https://github.com/XTLS/libXray/
import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

const USER_AGENT string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

type ParserFunc func(string) (*option.Outbound, error)

func getTLSOptions(decoded map[string]string) T.OutboundTLSOptionsContainer {
	if !(decoded["tls"] == "tls" || decoded["security"] == "tls" || decoded["security"] == "reality") {
		return T.OutboundTLSOptionsContainer{TLS: nil}
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
	insecure, err := getOneOf(decoded, "insecure", "allowinsecure")
	if err != nil {
		insecure = "false"
	}
	tlsOptions := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   insecure == "true" || insecure == "1",
		DisableSNI: serverName == "",
		ECH:        ECHOpts,
		// TLSTricks:  getTricksOptions(decoded),
	}
	if fp != "" && !tlsOptions.DisableSNI {
		tlsOptions.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fp,
		}
	}

	if alpn, ok := decoded["alpn"]; ok && alpn != "" {
		if net, _ := getOneOf(decoded, "net", "type"); net == "httpupgrade" || net == "ws" || net == "grpc" || net == "h2" {
			// tlsOptions.ALPN = []string{"http/1.1"}
		} else {
			tlsOptions.ALPN = strings.Split(alpn, ",")
			if getALPNversion(tlsOptions.ALPN) == 3 && getOneOfN(decoded, "", "type") == "xhttp" || getOneOfN(decoded, "", "net") == "xhttp" {
				tlsOptions.UTLS = nil //TODO utls quic has bug
			}
		}

	}
	return T.OutboundTLSOptionsContainer{
		TLS: tlsOptions,
	}

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
func getFragmentOptions(decoded map[string]string) option.TLSFragmentOptions {
	trick := option.TLSFragmentOptions{}
	fragment := decoded["fragment"]
	if fragment != "" {
		splt := strings.Split(fragment, ",")
		if len(splt) > 2 {
			if splt[0] == "tlshello" {
				trick.Size = splt[1]
				trick.Sleep = splt[2]
			} else {
				trick.Size = splt[0]
				trick.Sleep = splt[1]
			}
		}
	} else {
		trick.Size = decoded["fgsize"]
		trick.Sleep = decoded["fgsleep"]
	}
	if trick.Size != "" {
		trick.Enabled = true
	} else {
		trick.Enabled = false
	}

	return trick
}
func getMuxOptions(decoded map[string]string) *option.OutboundMultiplexOptions {
	mux := option.OutboundMultiplexOptions{}
	mux.Protocol = decoded["muxtype"]
	if mux.Protocol == "" {
		return nil
	}
	mux.Enabled = true
	mux.MaxConnections = toInt(decoded["muxmaxc"])
	// mux.MinStreams = toInt(decoded["muxsmin"])
	mux.MaxStreams = toInt(decoded["muxsmax"])
	mux.MinStreams = toInt(decoded["mux"])
	mux.Padding = decoded["muxpad"] == "true"

	if decoded["muxup"] != "" && decoded["muxdown"] != "" {
		mux.Brutal = &option.BrutalOptions{
			Enabled:  true,
			UpMbps:   toInt(decoded["muxup"]),
			DownMbps: toInt(decoded["muxdown"]),
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
		path = decoded["servicename"]
	}
	if net == "raw" || net == "" {
		net = "tcp"
	}
	// fmoption.Printf("\n\nheaderType:%s, net:%s, type:%s\n\n", decoded["headerType"], net, decoded["type"])
	if (decoded["type"] == "http" || decoded["headertype"] == "http") && net == "tcp" {
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
			transportOptions.HTTPOptions.Host = badoption.Listable[string]{host}
		}
		httpPath := path
		if httpPath == "" {
			httpPath = "/"
		}
		transportOptions.HTTPOptions.Path = httpPath
	case "httpupgrade":
		decoded["alpn"] = "http/1.1"
		transportOptions.Type = C.V2RayTransportTypeHTTPUpgrade
		if host != "" {
			transportOptions.HTTPUpgradeOptions.Headers = badoption.HTTPHeader{"Host": {host}}
		}
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			pathURL, err := url.Parse(path)
			if err != nil {
				return &option.V2RayTransportOptions{}, err
			}
			// pathQuery := pathURL.Query()
			// transportOptions.HTTPUpgradeOptions.MaxEarlyData = 0
			// transportOptions.HTTPUpgradeOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			// maxEarlyDataString := pathQuery.Get("ed")
			// if maxEarlyDataString != "" {
			// 	maxEarlyDate, err := strconv.ParseUint(maxEarlyDataString, 10, 32)
			// 	if err == nil {
			// 		// transportOptions.HTTPUpgradeOptions.MaxEarlyData = uint32(maxEarlyDate)
			// 		pathQuery.Del("ed")
			// 		pathURL.RawQuery = pathQuery.Encode()
			// 	}
			// }
			transportOptions.HTTPUpgradeOptions.Path = pathURL.String()
		}
	case "ws":
		decoded["alpn"] = "http/1.1"

		transportOptions.Type = C.V2RayTransportTypeWebsocket
		if host != "" {
			transportOptions.WebsocketOptions.Headers = badoption.HTTPHeader{"Host": {host}}
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
		decoded["alpn"] = "h2"
		transportOptions.Type = C.V2RayTransportTypeGRPC
		transportOptions.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName:         path,
			IdleTimeout:         badoption.Duration(15 * time.Second),
			PingTimeout:         badoption.Duration(15 * time.Second),
			PermitWithoutStream: false,
		}
	case "quic":
		decoded["alpn"] = "h3"
		transportOptions.Type = C.V2RayTransportTypeQUIC

	case "xhttp":
		transportOptions.Type = C.V2RayTransportTypeXHTTP
		transportOptions.XHTTPOptions = option.V2RayXHTTPOptions{
			Mode: getOneOfN(decoded, "auto", "mode"),
			V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
				Host: host,
				Path: path,
			},
		}

		if extra, ok := decoded["extra"]; ok {
			x := XHTTPExtra{}
			err := json.Unmarshal([]byte(extra), &x)
			if err != nil {
				return nil, err
			}
			transportOptions.XHTTPOptions.V2RayXHTTPBaseOptions = x.V2RayXHTTPBaseOptions
			if transportOptions.XHTTPOptions.Host == "" {
				transportOptions.XHTTPOptions.Host = host
			}
			if transportOptions.XHTTPOptions.Path == "" {
				transportOptions.XHTTPOptions.Path = path
			}
			if dl := x.DownloadSettings; dl != nil {
				transportOptions.XHTTPOptions.Download = &option.V2RayXHTTPDownloadOptions{
					V2RayXHTTPBaseOptions: dl.V2RayXHTTPBaseOptions,
					ServerOptions: option.ServerOptions{
						Server:     dl.Address,
						ServerPort: uint16(dl.Port),
					},
				}
				if transportOptions.XHTTPOptions.Download.Path == "" {
					transportOptions.XHTTPOptions.Download.Path = path
				}
				if dl.Security == "tls" && dl.TLSSettings != nil {
					transportOptions.XHTTPOptions.Download.TLS = &option.OutboundTLSOptions{
						Enabled:    true,
						ALPN:       dl.TLSSettings.ALPN,
						Insecure:   dl.TLSSettings.Insecure,
						ServerName: dl.TLSSettings.ServerName,
					}

					if dl.TLSSettings.Fingerprint != "" && getALPNversion(dl.TLSSettings.ALPN) != 3 {
						transportOptions.XHTTPOptions.Download.TLS.UTLS = &option.OutboundUTLSOptions{
							Enabled:     true,
							Fingerprint: dl.TLSSettings.Fingerprint,
						}
					}
				}
				if dl.Security == "reality" && dl.REALITYSettings != nil {
					transportOptions.XHTTPOptions.Download.TLS = &option.OutboundTLSOptions{
						Enabled: true,
						Reality: &option.OutboundRealityOptions{
							Enabled:   true,
							PublicKey: dl.REALITYSettings.PublicKey,
							ShortID:   dl.REALITYSettings.ShortId,
						},
						ServerName: dl.REALITYSettings.ServerName,
					}
					if dl.REALITYSettings.Fingerprint != "" {
						transportOptions.XHTTPOptions.Download.TLS.UTLS = &option.OutboundUTLSOptions{
							Enabled:     true,
							Fingerprint: dl.REALITYSettings.Fingerprint,
						}
					}
				}

			}

		}

		// 	var extraConfig option.V2RayXHTTPBaseOptions
		// 	err := json.Unmarshal([]byte(extra), &extraConfig)
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// 	if headers, ok := extraConfig["headers"]; ok {
		// 		if headersMap, ok := headers.(map[string]string); ok {
		// 			transportOptions.XHTTPOptions.Headers = make(badoption.HTTPHeader, len(headersMap))
		// 			for k, v := range headersMap {
		// 				transportOptions.XHTTPOptions.Headers[k] = badoption.Listable[string]{v}
		// 			}
		// 		}
		// 	}
		// 	if dlsettings, ok := extraConfig["downloadSettings"]; ok {
		// 		if dlsettingsMap, ok := dlsettings.(map[string]any); ok {
		// 			if addr, ok := dlsettingsMap["address"]; ok {
		// 				if addrs, ok := addr.(string); ok {
		// 					transportOptions.XHTTPOptions.DownloadServer = addrs
		// 				}
		// 			}
		// 			if port, ok := dlsettingsMap["port"]; ok {
		// 				if portInt, ok := port.(int); ok {
		// 					transportOptions.XHTTPOptions.DownloadServerPort = uint16(portInt)
		// 				} else if portuInt, ok := port.(uint16); ok {
		// 					transportOptions.XHTTPOptions.DownloadServerPort = portuInt
		// 				} else if ports, ok := port.(string); ok {
		// 					transportOptions.XHTTPOptions.DownloadServerPort = toUInt16(ports, 0)
		// 				}
		// 			}

		// 		}
		// 	}
		// 	if noGRPCHeader, ok := extraConfig["noGRPCHeader"]; ok {
		// 		if noGRPCHeaderb, ok := noGRPCHeader.(bool); ok {
		// 			transportOptions.XHTTPOptions.NoGRPCHeader = noGRPCHeaderb
		// 		}
		// 	}
		// 	if noSSEHeader, ok := extraConfig["noSSEHeader"]; ok {
		// 		if noSSEHeaderb, ok := noSSEHeader.(bool); ok {
		// 			transportOptions.XHTTPOptions.NoGRPCHeader = noSSEHeaderb
		// 		}
		// 	}

		// 	if scMaxBufferedPosts, ok := extraConfig["scMaxBufferedPosts"]; ok {
		// 		if scMaxBufferedPosti, ok := scMaxBufferedPosts.(int); ok {
		// 			transportOptions.XHTTPOptions.MaxEachPostBytes = uint64(scMaxBufferedPosti)
		// 		}
		// 	}

		// res["extra"] = extraConfig
		// }

	default:
		return nil, E.New("unknown transport type: " + net)
	}

	return &transportOptions, nil
}
func getALPNversion(s []string) int {
	if len(s) == 0 {
		return 1
	}
	if s[0] == "h3" {
		return 3
	}
	if s[0] == "h2" {
		return 2
	}
	return 1
}

// func getV2RayXHTTPBaseOptions(extraConfig map[string]any) option.V2RayXHTTPBaseOptions {
// 	opts := option.V2RayXHTTPBaseOptions{}
// 	if headers, ok := extraConfig["headers"]; ok {
// 		if headersMap, ok := headers.(map[string]string); ok {
// 			opts.Headers = headersMap
// 		}
// 	}

// 	if noGRPCHeader, ok := extraConfig["noGRPCHeader"]; ok {
// 		if noGRPCHeaderb, ok := noGRPCHeader.(bool); ok {
// 			opts.NoGRPCHeader = noGRPCHeaderb
// 		}
// 	}
// 	if noSSEHeader, ok := extraConfig["noSSEHeader"]; ok {
// 		if noSSEHeaderb, ok := noSSEHeader.(bool); ok {
// 			opts.NoGRPCHeader = noSSEHeaderb
// 		}
// 	}

//		if scMaxBufferedPosts, ok := extraConfig["scMaxBufferedPosts"]; ok {
//			if scMaxBufferedPosti, ok := scMaxBufferedPosts.(int); ok {
//				opts.ScMaxBufferedPosts = int64(scMaxBufferedPosti)
//			}
//		}
//	}
func getDialerOptions(decoded map[string]string) option.DialerOptions {
	fragment := getFragmentOptions(decoded)
	return T.DialerOptions{
		// TCPFastOpen: !fragment.Enabled,
		TLSFragment: fragment,
	}
}

func decodeBase64IfNeeded(b64string string) (string, error) {

	decodedBytes, err := decodeBase64FaultTolerant(b64string)

	if err != nil {
		return b64string, err
	}

	return string(decodedBytes), nil
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func toUInt16(s string, defaultPort uint16) uint16 {
	val, err := strconv.ParseInt(s, 10, 17)
	if err != nil {
		// fmoption.Printf("err %v", err)
		// handle the error appropriately; here we return 0
		return defaultPort
	}
	return uint16(val)
}

func toInt16(s string, defaultPort int16) int16 {
	val, err := strconv.ParseInt(s, 10, 17)
	if err != nil {
		// fmoption.Printf("err %v", err)
		// handle the error appropriately; here we return 0
		return defaultPort
	}
	return int16(val)
}

func isIPOnly(s string) bool {
	return net.ParseIP(s) != nil
}

func getOneOf(dic map[string]string, headers ...string) (string, error) {
	for _, h := range headers {
		if str, ok := dic[h]; ok {
			return str, nil
		}
	}
	return "", fmt.Errorf("not found")
}

func getOneOfN(dic map[string]string, defaultval string, headers ...string) string {
	for _, h := range headers {
		if str, ok := dic[h]; ok {
			return str
		}
	}
	return defaultval
}
