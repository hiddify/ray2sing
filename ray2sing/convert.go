package ray2sing

import (
	"fmt"
	"os"
	"runtime"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func detectType(input string) string {
	switch {
	case strings.HasPrefix(input, "vmess://"):
		return "vmess"
	case strings.HasPrefix(input, "vless://"):
		return "vless"
	case strings.HasPrefix(input, "trojan://"):
		return "trojan"
	case strings.HasPrefix(input, "ss://"):
		return "ss"
	case strings.HasPrefix(input, "tuic://"):
		return "tuic"
	}
	return ""
}

func parseConfig(input string) (map[string]string, error) {
	var parsedConfig map[string]string
	var err error
	switch detectType(input) {
	case "vmess":
		parsedConfig, err = decodeVmess(input)
	case "vless", "trojan":
		parsedConfig, err = parseProxyURL(input, detectType(input))
	case "ss":
		parsedConfig, err = parseShadowsocks(input)
	case "tuic":
		parsedConfig, err = parseTuic(input)
	}
	return parsedConfig, err
}

func decodeVmess(vmessConfig string) (map[string]string, error) {
	vmessData := vmessConfig[8:]
	decodedData, _ := base64.StdEncoding.DecodeString(vmessData)
	var data map[string]string
	json.Unmarshal(decodedData, &data)
	return data, nil
}

func parseProxyURL(inputURL string, protocol string) (map[string]string, error) {
	parsedURL, _ := url.Parse(inputURL)
	params := parsedURL.Query()
	output := map[string]string{
		"protocol": protocol,
		"username": parsedURL.User.Username(),
		"hostname": parsedURL.Hostname(),
		"port":     parsedURL.Port(),
		"hash":     parsedURL.Fragment,
	}
	for key, values := range params {
		// Assuming you want to concatenate multiple values with a comma (",") separator
		output[key] = strings.Join(values, ",")
	}
	return output, nil
}

func parseShadowsocks(configStr string) (map[string]string, error) {
	parsedURL, _ := url.Parse(configStr)
	userInfo, _ := base64.StdEncoding.DecodeString(parsedURL.User.String())
	userDetails := strings.Split(string(userInfo), ":")
	server := map[string]string{
		"encryption_method": userDetails[0],
		"password":          userDetails[1],
		"server_address":    parsedURL.Hostname(),
		"server_port":       parsedURL.Port(),
		"name":              parsedURL.Fragment,
	}
	return server, nil
}

func parseTuic(configStr string) (map[string]string, error) {
	parsedURL, _ := url.Parse(configStr)
	params := parsedURL.Query()
	user := parsedURL.User
	var password string
	if user != nil {
		password, _ = user.Password()
	}

	output := map[string]string{
		"protocol": "tuic",
		"username": parsedURL.User.Username(),
		"password": password, // Assign the password string here
		"hostname": parsedURL.Hostname(),
		"port":     parsedURL.Port(),
		"hash":     parsedURL.Fragment,
	}
	for key, values := range params {
		// Assuming you want to concatenate multiple values with a comma (",") separator
		output[key] = strings.Join(values, ",")
	}

	return output, nil
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
	ipv4Pattern := `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`
	ipv6Pattern := `^[0-9a-fA-F:]+$`
	if matched, _ := regexp.MatchString(ipv4Pattern, address); matched {
		return true
	}
	if matched, _ := regexp.MatchString(ipv6Pattern, address); matched {
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
	rand.Seed(time.Now().UnixNano())
	randomNumbers := make(map[int]bool)
	var uniqueNumbers []int

	for len(uniqueNumbers) < count {
		number := rand.Intn(max + 1)
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
	val, err := strconv.ParseInt(s, 10, 16)
	if err != nil {
		// handle the error appropriately; here we return 0
		return 0
	}
	return uint16(val)
}

func getTransportOptions(decoded map[string]string) (*T.V2RayTransportOptions, error) {
	var transportOptions T.V2RayTransportOptions
	host, net, path := decoded["host"], decoded["net"], decoded["path"]
	if net == "" {
		net = decoded["type"]
	}
	if path == "" {
		path = decoded["serviceName"]
	}
	switch net {
	case "tcp":
		return nil, nil
	case "http":
		transportOptions.Type = C.V2RayTransportTypeHTTP
		transportOptions.HTTPOptions = T.V2RayHTTPOptions{
			Path:    path,
			Headers: map[string]T.Listable[string]{"Host": {host}},
		}
	case "ws":
		transportOptions.Type = C.V2RayTransportTypeWebsocket
		transportOptions.WebsocketOptions = T.V2RayWebsocketOptions{
			Path:                path,
			Headers:             map[string]T.Listable[string]{"Host": {host}},
			MaxEarlyData:        0,
			EarlyDataHeaderName: "Sec-WebSocket-Protocol",
		}
	case "grpc":
		transportOptions.Type = C.V2RayTransportTypeGRPC
		transportOptions.GRPCOptions = T.V2RayGRPCOptions{
			ServiceName:         path,
			IdleTimeout:         T.Duration(15 * time.Second),
			PingTimeout:         T.Duration(15 * time.Second),
			PermitWithoutStream: false,
		}
	default:
		return nil, E.New("unknown transport type: " + net)
	}

	return &transportOptions, nil
}

func getTLSOptions(decoded map[string]string) *T.OutboundTLSOptions {
	if !(decoded["tls"] == "tls" || decoded["security"] == "tls" || decoded["security"] == "reality") {
		return nil
	}

	serverName := decoded["sni"]
	if serverName == "" {
		serverName = decoded["add"]
	}
	if serverName == "" {
		serverName = decoded["sni"]
	}

	_, hasECH := decoded["ech"]

	tlsOptions := &T.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   true,
		DisableSNI: false,
		UTLS: &T.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
		ECH: &T.OutboundECHOptions{
			Enabled: hasECH,
		},
	}

	if alpn, ok := decoded["alpn"]; ok && alpn != "" {
		tlsOptions.ALPN = strings.Split(alpn, ",")
	}

	return tlsOptions
}

func fixName(name string) string {
	if name == "" {
		name = "-"
	}
	return name
}

func VmessSingbox(vmessURL string) (T.Outbound, error) {
	decoded, err := decodeVmess(vmessURL)
	if err != nil {
		return T.Outbound{}, err
	}

	port := toInt16(decoded["port"])
	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return T.Outbound{}, err
	}

	return T.Outbound{
		Tag:  fixName(decoded["ps"]),
		Type: "vmess",
		VMessOptions: T.VMessOutboundOptions{
			DialerOptions: T.DialerOptions{},
			ServerOptions: T.ServerOptions{
				Server:     decoded["add"],
				ServerPort: port,
			},
			UUID:                decoded["id"],
			Security:            "auto",
			AlterId:             toInt(decoded["aid"]),
			GlobalPadding:       false,
			AuthenticatedLength: true,
			PacketEncoding:      "xudp",
			TLS:                 getTLSOptions(decoded),
			Transport:           transportOptions,
		},
	}, nil
}

func VlessSingbox(vlessURL string) (T.Outbound, error) {
	decoded, err := parseProxyURL(vlessURL, "vless")
	if err != nil {
		return T.Outbound{}, err
	}

	port := toInt16(decoded["port"])
	transportOptions, err := getTransportOptions(decoded)
	tlsOptions := getTLSOptions(decoded)
	if tlsOptions != nil {
		if security := decoded["security"]; security == "reality" {
			tlsOptions.Reality = &T.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: decoded["pbk"],
				ShortID:   decoded["sid"],
			}
		}
	}

	xudp := "xudp"
	return T.Outbound{
		Tag:  fixName(decoded["hash"]),
		Type: "vless",
		VLESSOptions: T.VLESSOutboundOptions{
			DialerOptions: T.DialerOptions{},
			ServerOptions: T.ServerOptions{
				Server:     decoded["hostname"],
				ServerPort: port,
			},
			UUID:           decoded["username"],
			PacketEncoding: &xudp,
			Flow:           decoded["flow"],
			TLS:            tlsOptions,
			Transport:      transportOptions,
		},
	}, nil
}

func TrojanSingbox(trojanURL string) (T.Outbound, error) {
	decoded, err := parseProxyURL(trojanURL, "trojan")
	if err != nil {
		return T.Outbound{}, err
	}

	port := toInt16(decoded["port"])
	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return T.Outbound{}, err
	}

	return T.Outbound{
		Tag:  fixName(decoded["hash"]),
		Type: "trojan",
		TrojanOptions: T.TrojanOutboundOptions{
			DialerOptions: T.DialerOptions{},
			ServerOptions: T.ServerOptions{
				Server:     decoded["hostname"],
				ServerPort: port,
			},
			Password:  decoded["username"],
			TLS:       getTLSOptions(decoded),
			Transport: transportOptions,
		},
	}, nil
}

func getPath(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func ShadowsocksSingbox(shadowsocksUrl string) (T.Outbound, error) {
	decoded, err := parseShadowsocks(shadowsocksUrl)
	if err != nil {
		return T.Outbound{}, err
	}

	defaultMethod := "chacha20-ietf-poly1305"
	if decoded["encryption_method"] != "" {
		defaultMethod = decoded["encryption_method"]
	}

	result := T.Outbound{
		Type: "shadowsocks",
		Tag:  fixName(decoded["name"]),
		ShadowsocksOptions: T.ShadowsocksOutboundOptions{
			ServerOptions: T.ServerOptions{
				Server:     decoded["server"],
				ServerPort: toInt16(decoded["port"]),
			},
			Method:        defaultMethod,
			Password:      decoded["password"],
			Plugin:        decoded["plugin"],
			PluginOptions: decoded["plugin_opts"],
		},
	}

	return result, nil
}

func TuicSingbox(tuicUrl string) (T.Outbound, error) {
	decoded, err := parseTuic(tuicUrl)
	if err != nil {
		return T.Outbound{}, err
	}

	result := T.Outbound{
		Type: "tuic",
		Tag:  fixName(decoded["name"]),
		TUICOptions: T.TUICOutboundOptions{
			ServerOptions: T.ServerOptions{
				Server:     decoded["hostname"],
				ServerPort: toInt16(decoded["port"]),
			},
			UUID:              decoded["username"],
			Password:          decoded["password"],
			CongestionControl: decoded["congestion_control"],
			UDPRelayMode:      decoded["udp_relay_mode"],
			ZeroRTTHandshake:  false,
			Heartbeat:         T.Duration(10 * time.Second),
			TLS: &T.OutboundTLSOptions{
				Enabled:    true,
				DisableSNI: decoded["sni"] == "",
				ServerName: decoded["sni"],
				Insecure:   decoded["allow_insecure"] == "1",
				ALPN:       []string{"h3", "spdy/3.1"},
			},
		},
	}

	return result, nil
}

func processSingleConfig(config string) (outbound T.Outbound, err error) {
	defer func() {
		if r := recover(); r != nil {
			outbound = T.Outbound{}
			stackTrace := make([]byte, 1024)
			runtime.Stack(stackTrace, false)
			err = fmt.Errorf("Error in Parsing: %+v\nStack trace:\n%s", r, stackTrace)
		}
	}()
	configType := detectType(config)
	config, err = url.QueryUnescape(config)
	if err != nil {
		return T.Outbound{}, err
	}
	var configSingbox T.Outbound
	switch configType {
	case "vmess":
		configSingbox, err = VmessSingbox(config)
	case "vless":
		configSingbox, err = VlessSingbox(config)
	case "trojan":
		configSingbox, err = TrojanSingbox(config)
	case "ss":
		configSingbox, err = ShadowsocksSingbox(config)
	case "tuic":
		configSingbox, err = TuicSingbox(config)
	default:
		return T.Outbound{}, E.New("Not supported config type")
	}
	if err != nil {
		return T.Outbound{}, err
	}
	json.MarshalIndent(configSingbox, "", "  ")
	return configSingbox, nil
}
func GenerateConfigLite(input string) (string, error) {

	// v2raySubscription := url.QueryEscape(input)

	configArray := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")

	var outbounds []T.Outbound
	for counter, config := range configArray {
		//
		configSingbox, err := processSingleConfig(config)
		// fmt.Printf("======configSingbox: %+v\n", configSingbox)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in %s \n %v\n", config, err)
			continue
		}
		configSingbox.Tag += " | " + strconv.Itoa(counter)
		outbounds = append(outbounds, configSingbox)

	}
	if len(outbounds) == 0 {
		return "", E.New("No outbounds found")
	}
	fullConfig := T.Options{
		Outbounds: outbounds,
	}

	jsonOutbound, err := json.MarshalIndent(fullConfig, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonOutbound), nil
}

func Ray2Singbox(configs string) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = ""
			stackTrace := make([]byte, 1024)
			runtime.Stack(stackTrace, false)
			err = fmt.Errorf("Error in Parsing %s: %+v\nStack trace:\n%s", configs, r, stackTrace)
		}
	}()
	configData := configs

	conf, err := base64.StdEncoding.DecodeString(configs)
	// fmt.Printf("decode: %s\n", string(conf))
	if err == nil {
		configData = string(conf)
	}
	convertedData, err := GenerateConfigLite(configData)
	return convertedData, err
}
