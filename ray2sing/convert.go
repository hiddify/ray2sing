package ray2sing

import (
	"fmt"

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

// ... (ipInfo and getFlags functions will go here, but they involve API calls and more complex logic)

func isBase64Encoded(s string) bool {
	if s == base64.StdEncoding.EncodeToString([]byte(s)) {
		return true
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

func getVmessV2RayTransportOptions(decodedVmess map[string]string) (T.V2RayTransportOptions, error) {
	var transportOptions T.V2RayTransportOptions
	var host = decodedVmess["host"]
	// Populate the transport options based on the "net" field in decodedVmess
	switch decodedVmess["net"] {
	case "http":
		transportOptions.Type = C.V2RayTransportTypeHTTP
		transportOptions.HTTPOptions = T.V2RayHTTPOptions{
			Path:    decodedVmess["path"],
			Headers: map[string]T.Listable[string]{"Host": {host}},
		}
	case "ws":
		transportOptions.Type = C.V2RayTransportTypeWebsocket
		transportOptions.WebsocketOptions = T.V2RayWebsocketOptions{
			Path:                decodedVmess["path"],
			Headers:             map[string]T.Listable[string]{"Host": {host}},
			MaxEarlyData:        0,                        // You can set this value accordingly
			EarlyDataHeaderName: "Sec-WebSocket-Protocol", // You can set this value accordingly
		}
	case "grpc":
		transportOptions.Type = C.V2RayTransportTypeGRPC
		transportOptions.GRPCOptions = T.V2RayGRPCOptions{
			ServiceName:         decodedVmess["path"],
			IdleTimeout:         T.Duration(15 * time.Second),
			PingTimeout:         T.Duration(15 * time.Second),
			PermitWithoutStream: false,
		}
	// Handle other cases as needed
	default:
		return transportOptions, E.New("unknown transport type: " + decodedVmess["net"])
	}

	return transportOptions, nil
}
func VmessSingbox(vmessURL string, counter int) (T.Outbound, error) {
	decoded, err := decodeVmess(vmessURL)
	if err != nil {
		return T.Outbound{}, err
	}
	port := toInt16(decoded["port"])
	result := T.Outbound{
		Tag:  fixName(decoded["ps"], counter),
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
		},
	}

	if port == 443 || decoded["tls"] == "tls" {
		var serverName string
		if sni, ok := decoded["sni"]; ok && sni != "" {
			serverName = sni
		} else {
			serverName = decoded["add"]
		}
		result.VMessOptions.TLS = &T.OutboundTLSOptions{
			Enabled:    true,
			ServerName: serverName,
			Insecure:   true,
			DisableSNI: false,
			UTLS: &T.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: "chrome",
			},
		}
		if decoded["alpn"] != "" {
			result.VMessOptions.TLS.ALPN = strings.Split(decoded["alpn"], ",")
		}

	}
	transport, err := getVmessV2RayTransportOptions(decoded)
	if err != nil {
		result.VMessOptions.Transport = &transport
	}

	return result, nil
}
func fixName(name string, counter int) string {
	if name == "" {
		name = "-"
	}
	return name + " | " + strconv.Itoa(counter)
}
func VlessSingbox(vlessURL string, counter int) (T.Outbound, error) {
	decoded, err := parseProxyURL(vlessURL, "vless")
	if err != nil {
		return T.Outbound{}, err
	}

	port := toInt16(decoded["port"])

	xudp := "xudp"

	result := T.Outbound{
		Tag:  fixName(decoded["hash"], counter),
		Type: "vless",
		VLESSOptions: T.VLESSOutboundOptions{
			DialerOptions: T.DialerOptions{},
			ServerOptions: T.ServerOptions{
				Server:     decoded["hostname"],
				ServerPort: port,
			},
			UUID:           decoded["username"],
			PacketEncoding: &xudp,
		},
	}
	if decoded["flow"] != "" {
		result.VLESSOptions.Flow = "xtls-rprx-vision"
	}

	security := decoded["security"]
	if port == 443 || security == "tls" || security == "reality" {
		result.VLESSOptions.TLS = &T.OutboundTLSOptions{
			Enabled:    true,
			ServerName: decoded["sni"],
			Insecure:   false,
			DisableSNI: false,
			UTLS: &T.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: "chrome",
			},
		}
		if security == "reality" {
			result.VLESSOptions.TLS.Reality = &T.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: decoded["pbk"],
				ShortID:   decoded["sid"],
			}
		}
		if decoded["alpn"] != "" {
			result.VLESSOptions.TLS.ALPN = strings.Split(decoded["alpn"], ",")
		}
	}
	if decoded["type"] == "ws" || decoded["type"] == "grpc" {

		result.VLESSOptions.Transport = &T.V2RayTransportOptions{
			Type: decoded["type"], // Assuming the type is specified in the params map
			WebsocketOptions: T.V2RayWebsocketOptions{
				Path:                decoded["path"],
				Headers:             map[string]T.Listable[string]{"Host": {decoded["host"]}},
				MaxEarlyData:        0,
				EarlyDataHeaderName: "Sec-WebSocket-Protocol",
			},
			GRPCOptions: T.V2RayGRPCOptions{
				ServiceName:         decoded["serviceName"],
				IdleTimeout:         T.Duration(15 * time.Second),
				PingTimeout:         T.Duration(15 * time.Second),
				PermitWithoutStream: false,
			},
		}
	}

	return result, nil
}

func TrojanSingbox(trojanUrl string, counter int) (T.Outbound, error) {
	decoded, err := parseProxyURL(trojanUrl, "trojan")
	if err != nil {
		return T.Outbound{}, err
	}

	port := toInt16(decoded["port"])

	result := T.Outbound{
		Tag:  fixName(decoded["hash"], counter),
		Type: "trojan",
		TrojanOptions: T.TrojanOutboundOptions{
			DialerOptions: T.DialerOptions{},
			ServerOptions: T.ServerOptions{
				Server:     decoded["hostname"],
				ServerPort: port,
			},
			Password: decoded["username"],
		},
	}
	security := decoded["security"]
	if port == 443 || security == "tls" {
		result.TrojanOptions.TLS = &T.OutboundTLSOptions{
			Enabled:    true,
			ServerName: decoded["sni"],
			Insecure:   false,
			DisableSNI: false,
			UTLS: &T.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: "chrome",
			},
		}
		if decoded["alpn"] != "" {
			result.TrojanOptions.TLS.ALPN = strings.Split(decoded["alpn"], ",")
		}
	}
	if decoded["type"] == "ws" || decoded["type"] == "grpc" {

		result.TrojanOptions.Transport = &T.V2RayTransportOptions{
			Type: decoded["type"], // Assuming the type is specified in the params map
			WebsocketOptions: T.V2RayWebsocketOptions{
				Path:                decoded["path"],
				Headers:             map[string]T.Listable[string]{"Host": {decoded["host"]}},
				MaxEarlyData:        0,
				EarlyDataHeaderName: "Sec-WebSocket-Protocol",
			},
			GRPCOptions: T.V2RayGRPCOptions{
				ServiceName:         decoded["serviceName"],
				IdleTimeout:         T.Duration(15 * time.Second),
				PingTimeout:         T.Duration(15 * time.Second),
				PermitWithoutStream: false,
			},
		}
	}
	return result, nil
}

func getPath(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func ShadowsocksSingbox(shadowsocksUrl string, counter int) (T.Outbound, error) {
	decoded, err := parseShadowsocks(shadowsocksUrl)
	if err != nil {
		return T.Outbound{}, err
	}

	if decoded["name"] == "" {
		decoded["name"] = "-"
	}
	name := decoded["name"] + " | " + strconv.Itoa(counter)

	defaultMethod := "chacha20-ietf-poly1305"
	if decoded["encryption_method"] != "" {
		defaultMethod = decoded["encryption_method"]
	}

	result := T.Outbound{
		Type: "shadowsocks",
		Tag:  name,
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

func TuicSingbox(tuicUrl string, counter int) (T.Outbound, error) {
	decoded, err := parseTuic(tuicUrl)
	if err != nil {
		return T.Outbound{}, err
	}
	if decoded["name"] == "" {
		decoded["name"] = "-"
	}
	name := decoded["name"] + " | " + strconv.Itoa(counter)

	result := T.Outbound{
		Type: "tuic",
		Tag:  name,
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

func GenerateConfigLite(input string) (string, error) {

	// v2raySubscription := url.QueryEscape(input)

	configArray := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")

	var outbounds []T.Outbound
	for counter, config := range configArray {
		fmt.Printf("======config: %s\n", config)
		configType := detectType(config)
		var err error
		config, err = url.QueryUnescape(config)
		var configSingbox T.Outbound

		switch configType {
		case "vmess":
			configSingbox, err = VmessSingbox(config, counter)
		case "vless":
			configSingbox, err = VlessSingbox(config, counter)
		case "trojan":
			configSingbox, err = TrojanSingbox(config, counter)
		case "ss":
			configSingbox, err = ShadowsocksSingbox(config, counter)
		case "tuic":
			configSingbox, err = TuicSingbox(config, counter)
		default:
			configSingbox, err = T.Outbound{}, E.New("Not supported config type")
		}
		fmt.Printf("======configSingbox: %+v\n", configSingbox)
		if err == nil {

			outbounds = append(outbounds, configSingbox)
			a, _ := json.MarshalIndent(configSingbox, "", "  ")
			fmt.Println(string(a))
		}
	}

	jsonOutbound, err := json.MarshalIndent(outbounds, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonOutbound), nil
}

func Ray2Singbox(configs string) (string, error) {
	configData := configs
	if isBase64Encoded(configs) {
		conf, err := base64.StdEncoding.DecodeString(configs)
		if err != nil {
			return "", err
		}
		configData = string(conf)
	}

	convertedData, err := GenerateConfigLite(configData)
	return convertedData, err
}
