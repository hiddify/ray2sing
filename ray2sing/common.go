package ray2sing

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"strings"
	"time"
)

type ParserFunc func(string) (*T.Outbound, error)

func getTLSOptions(decoded map[string]string) *T.OutboundTLSOptions {
	if !(decoded["tls"] == "tls" || decoded["security"] == "tls" || decoded["security"] == "reality") {
		return nil
	}

	serverName := decoded["sni"]
	if serverName == "" {
		serverName = decoded["add"]
	}

	var ECHOpts *T.OutboundECHOptions
	valECH, hasECH := decoded["ech"]
	if hasECH && (valECH != "0") {
		ECHOpts = &T.OutboundECHOptions{
			Enabled: true,
		}
	}

	tlsOptions := &T.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   true,
		DisableSNI: false,
		UTLS: &T.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
		ECH: ECHOpts,
	}

	if alpn, ok := decoded["alpn"]; ok && alpn != "" {
		tlsOptions.ALPN = strings.Split(alpn, ",")
	}

	return tlsOptions
}

func getTransportOptions(decoded map[string]string) (*T.V2RayTransportOptions, error) {
	var transportOptions T.V2RayTransportOptions
	// fmt.Printf("=======%v", decoded)
	host, net, path := decoded["host"], decoded["net"], decoded["path"]
	if net == "" {
		net = decoded["type"]
	}
	if path == "" {
		path = decoded["serviceName"]
	}
	// fmt.Printf("\n\nheaderType:%s, net:%s, type:%s\n\n", decoded["headerType"], net, decoded["type"])
	if (decoded["type"] == "http" || decoded["headerType"] == "http") && net == "tcp" {
		net = "http"
	}

	switch net {
	case "tcp":
		return nil, nil
	case "http":
		httpPath := path
		if httpPath == "" {
			httpPath = "/"
		}
		transportOptions.Type = C.V2RayTransportTypeHTTP
		transportOptions.HTTPOptions = T.V2RayHTTPOptions{
			Path:    httpPath,
			Headers: map[string]T.Listable[string]{"Host": {host}},
		}
	case "ws":
		transportOptions.Type = C.V2RayTransportTypeWebsocket
		if host != "" {
			transportOptions.WebsocketOptions.Headers = map[string]T.Listable[string]{"Host": {host}}
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
			maxEarlyDataString := pathQuery.Get("ed")
			if maxEarlyDataString != "" {
				maxEarlyDate, err := strconv.ParseUint(maxEarlyDataString, 10, 32)
				if err == nil {
					transportOptions.WebsocketOptions.MaxEarlyData = uint32(maxEarlyDate)
					transportOptions.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
					pathQuery.Del("ed")
					pathURL.RawQuery = pathQuery.Encode()
				}
			}
			transportOptions.WebsocketOptions.Path = pathURL.String()
		}
	case "grpc":
		transportOptions.Type = C.V2RayTransportTypeGRPC
		transportOptions.GRPCOptions = T.V2RayGRPCOptions{
			ServiceName:         path,
			IdleTimeout:         T.Duration(15 * time.Second),
			PingTimeout:         T.Duration(15 * time.Second),
			PermitWithoutStream: false,
		}
	case "quic":
		transportOptions.Type = C.V2RayTransportTypeQUIC
	default:
		return nil, E.New("unknown transport type: " + net)
	}

	return &transportOptions, nil
}

func processPath(path string) (string, uint32) {
	// Compile the regular expression to find 'ed=number'
	re := regexp.MustCompile(`[?&]ed=(\d+)`)

	// Find the first match
	match := re.FindStringSubmatch(path)

	if len(match) > 1 {
		// Convert the captured string to an integer
		ed, err := strconv.Atoi(match[1])
		if err != nil {
			// Handle the error if conversion fails
			fmt.Println("Error converting number:", err)
			return path, 0
		}

		// Remove 'ed=number' from the path
		newPath := re.ReplaceAllString(path, "")

		return newPath, uint32(ed)
	}

	// Return the original path and 0 if 'ed=number' is not found
	return path, 0
}

func generateName(fragment string, configType string) string {
	if fragment != "" {
		return fragment
	}
	return fmt.Sprintf("%v-%v", configType, time.Now().UnixNano())
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

func isNumberWithDots(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789.", c) {
			return false
		}
	}
	return true
}

func isValidAddress(address string) bool {
	if isIPOnly(address) {
		return true
	}
	if !isNumberWithDots(address) {
		if strings.HasPrefix(address, "https://") || strings.HasPrefix(address, "http://") {
			_, err := url.ParseRequestURI(address)
			return err == nil
		}
		_, err := url.ParseRequestURI("https://" + address)
		return err == nil
	}
	return false
}

func generateUniqueRandomNumbers(max int, count int) []int {
	randGen := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomNumbers := make(map[int]bool)
	var uniqueNumbers []int

	for len(uniqueNumbers) < count {
		number := randGen.Intn(max + 1)
		if !randomNumbers[number] {
			randomNumbers[number] = true
			uniqueNumbers = append(uniqueNumbers, number)
		}
	}

	sort.Ints(uniqueNumbers)

	return uniqueNumbers
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func toInt16(s string) uint16 {
	val, err := strconv.ParseInt(s, 10, 17)
	if err != nil {
		// fmt.Printf("err %v", err)
		// handle the error appropriately; here we return 0
		return 443
	}
	return uint16(val)
}

func isIPOnly(s string) bool {
	return net.ParseIP(s) != nil
}
