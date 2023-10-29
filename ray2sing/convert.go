package ray2sing

import (
	"fmt"
	"net"
	"os"
	"runtime"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var configTypes = map[string]string{
	"vmess://":     "vmess",
	"vless://":     "vless",
	"trojan://":    "trojan",
	"ss://":        "ss",
	"tuic://":      "tuic",
	"hysteria2://": "hysteria2",
	"hy2://":       "hysteria2",
	"ssh://":       "ssh",
	"wg://":        "wireguard",
}

func detectType(input string) string {
	for k, v := range configTypes {
		if strings.HasPrefix(input, k) {
			return v
		}
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
	case "hysteria2":
		parsedConfig, err = parseHysteria2(input)
	case "ssh":
		parsedConfig, err = parseSSH(input)
	case "wireguard":
		parsedConfig, err = parseWireguard(input)
	}
	return parsedConfig, err
}

func generateName(fragment string, configType string) string {
	if fragment != "" {
		return fragment
	}
	return fmt.Sprintf("%v-%v", configType, time.Now().UnixNano())
}

func fixName(name string) string {
	if name == "" {
		return fmt.Sprintf("unnamed-%v", time.Now().UnixNano())
	}
	return name
}

func parseSSH(inputURL string) (result map[string]string, err error) {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return
	}
	params := parsedURL.Query()
	password, ok := parsedURL.User.Password()
	if !ok {
		password = ""
	}
	result = map[string]string{
		"protocol": "ssh",
		"username": parsedURL.User.Username(),
		"password": password,
		"hostname": parsedURL.Hostname(),
		"port":     parsedURL.Port(),
		"name":     generateName(parsedURL.Fragment, "SSH"),
	}
	for key, values := range params {
		result[key] = strings.Join(values, ",")
	}
	if _, ok = result["hk"]; !ok {
		err = fmt.Errorf("Failed to parse SSH URL: HostKey not provided")
		return
	}
	return
}

func parseWireguard(inputURL string) (result map[string]string, err error) {
	return nil, fmt.Errorf("Not Implemented")
}

func decodeVmess(vmessConfig string) (map[string]string, error) {
	vmessData := vmessConfig[8:]
	decodedData, err := base64.StdEncoding.DecodeString(vmessData)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	json.Unmarshal(decodedData, &data)
	strdata := convertToStrings(data)
	// fmt.Printf("----%v---", strdata)
	return strdata, nil
}

func convertToStrings(data map[string]interface{}) map[string]string {
	stringMap := make(map[string]string)
	for key, value := range data {
		switch v := value.(type) {
		case string:
			stringMap[key] = v
		case float64:
			stringMap[key] = strconv.Itoa(int(v))
		// case map[string]interface{}:
		// 	stringMap[key] = convertToStrings(v)

		default:
			stringMap[key] = fmt.Sprintf("%v", v)
		}
	}
	return stringMap

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
	// fmt.Printf("====%v", output)
	return output, nil
}

func parseHysteria2(inputURL string) (result map[string]string, err error) {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return
	}
	params := parsedURL.Query()
	name := parsedURL.Fragment
	if name == "" {
		name = fmt.Sprintf("hysteria2-%v", time.Now().UnixNano())
	}
	result = map[string]string{
		"protocol": "hysteria2",
		"password": parsedURL.User.String(),
		"hostname": parsedURL.Hostname(),
		"port":     parsedURL.Port(),
		"name":     name,
	}
	for key, values := range params {
		result[key] = strings.Join(values, ",")
	}

	return
}

func parseShadowsocks(configStr string) (map[string]string, error) {
	parsedURL, _ := url.Parse(configStr)
	var encryption_method string
	var password string

	userInfo, err := base64.StdEncoding.DecodeString(parsedURL.User.String())
	if err != nil {
		// If there's an error in decoding, use the original string
		encryption_method = parsedURL.User.Username()
		password, _ = parsedURL.User.Password()
	} else {
		// If decoding is successful, use the decoded string
		userDetails := strings.Split(string(userInfo), ":")
		encryption_method = userDetails[0]
		password = userDetails[1]
	}

	server := map[string]string{
		"encryption_method": encryption_method,
		"password":          password,
		"server":            parsedURL.Hostname(),
		"port":              parsedURL.Port(),
		"name":              parsedURL.Fragment,
	}
	// fmt.Printf("MMMM %v", server)
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
		return 0
	}
	return uint16(val)
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

	valECH, hasECH := decoded["ech"]
	hasECH = hasECH && (valECH != "0")
	var ECHOpts *T.OutboundECHOptions
	ECHOpts = nil
	if hasECH {
		ECHOpts = &T.OutboundECHOptions{
			Enabled: hasECH,
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

func VmessSingbox(vmessURL string) (T.Outbound, error) {
	decoded, err := decodeVmess(vmessURL)
	if err != nil {
		return T.Outbound{}, err
	}
	// fmt.Printf("port:%v", decoded["port"])
	port := toInt16(decoded["port"])
	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return T.Outbound{}, err
	}
	security := "auto"
	if decoded["scy"] != "" {
		security = decoded["scy"]
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
			Security:            security,
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
	// fmt.Printf("Port %v deco=%v", port, decoded)
	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return T.Outbound{}, err
	}

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

	valECH, hasECH := decoded["ech"]
	hasECH = hasECH && (valECH != "0")
	var ECHOpts *T.OutboundECHOptions
	ECHOpts = nil
	if hasECH {
		ECHOpts = &T.OutboundECHOptions{
			Enabled: hasECH,
		}
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
				ECH:        ECHOpts,
			},
		},
	}

	return result, nil
}

func isIPOnly(s string) bool {
	return net.ParseIP(s) != nil
}

func Hysteria2Singbox(hysteria2Url string) (T.Outbound, error) {
	decoded, err := parseHysteria2(hysteria2Url)
	if err != nil {
		return T.Outbound{}, err
	}
	var ObfsOpts *T.Hysteria2Obfs
	ObfsOpts = nil
	if obfs, ok := decoded["obfs"]; ok && obfs != "" {
		ObfsOpts = &T.Hysteria2Obfs{
			Type:     obfs,
			Password: decoded["obfs-password"],
		}
	}

	valECH, hasECH := decoded["ech"]
	hasECH = hasECH && (valECH != "0")
	var ECHOpts *T.OutboundECHOptions
	ECHOpts = nil
	if hasECH {
		ECHOpts = &T.OutboundECHOptions{
			Enabled: hasECH,
		}
	}

	SNI := decoded["sni"]
	if SNI == "" {
		SNI = decoded["hostname"]
	}

	result := T.Outbound{
		Type: "hysteria2",
		Tag:  decoded["name"],
		Hysteria2Options: T.Hysteria2OutboundOptions{
			ServerOptions: T.ServerOptions{
				Server:     decoded["hostname"],
				ServerPort: toInt16(decoded["port"]),
			},
			Obfs:     ObfsOpts,
			Password: decoded["password"],
			TLS: &T.OutboundTLSOptions{
				Enabled:    true,
				Insecure:   decoded["insecure"] == "1",
				DisableSNI: isIPOnly(SNI),
				ServerName: SNI,
				ECH:        ECHOpts,
			},
		},
	}
	return result, nil
}

func SSHSingbox(sshURL string) (T.Outbound, error) {
	decoded, err := parseSSH(sshURL)
	if err != nil {
		return T.Outbound{}, err
	}
	prefix := "-----BEGIN OPENSSH PRIVATE KEY-----\n"
	suffix := "\n-----END OPENSSH PRIVATE KEY-----\n"

	privkeys := strings.Split(decoded["pk"], ",")
	if len(privkeys) == 1 && privkeys[0] == "" {
		privkeys = []string{}
	}
	for i := 0; i < len(privkeys); i++ {
		privkeys[i] = prefix + privkeys[i] + suffix
	}

	hostkeys := strings.Split(decoded["hk"], ",")

	result := T.Outbound{
		Type: "ssh",
		Tag:  decoded["name"],
		SSHOptions: T.SSHOutboundOptions{
			ServerOptions: T.ServerOptions{
				Server:     decoded["hostname"],
				ServerPort: toInt16(decoded["port"]),
			},
			User:       decoded["username"],
			Password:   decoded["password"],
			PrivateKey: privkeys,
			HostKey:    hostkeys,
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
	// fmt.Print(configType)
	// if configType != "vmess" {
	// config, err = url.QueryUnescape(config)
	// 	if err != nil {
	// 		return T.Outbound{}, err
	// 	}
	// }

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
	case "hysteria2":
		configSingbox, err = Hysteria2Singbox(config)
	case "ssh":
		configSingbox, err = SSHSingbox(config)
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
	// print(input)
	configArray := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")
	// print(configArray)
	var outbounds []T.Outbound
	for counter, config := range configArray {
		//
		configSingbox, err := processSingleConfig(config)
		// fmt.Printf("======configSingbox: %+v\n", configSingbox)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in %s \n %v\n", config, err)
			continue
		}
		configSingbox.Tag += " § " + strconv.Itoa(counter)
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
