package ray2sing

import (
	E "github.com/sagernet/sing/common/exceptions"

	"strings"
)

func getTLSOptionsXray(decoded map[string]string) map[string]any {
	if !(decoded["tls"] == "tls" || decoded["security"] == "tls") {
		return nil
	}
	serverName := decoded["sni"]
	if serverName == "" {
		serverName = decoded["add"]
	}
	alpn := []string{"h2", "http/1.1"}
	if alpnlink, ok := decoded["alpn"]; ok && alpnlink != "" {
		alpn = strings.Split(alpnlink, ",")
	}

	fp := decoded["fp"]
	if fp == "" {
		// fp = "chrome"
	}

	return map[string]any{
		"serverName":       serverName,
		"rejectUnknownSni": false,
		"allowInsecure":    decoded["insecure"] == "true",
		"alpn":             alpn,
		// "minVersion": "1.2",
		// "maxVersion": "1.3",
		// "disableSystemRoot": false,
		// "enableSessionResumption": true,
		"fingerprint": fp,
	}
}
func getRealityOptionsXray(decoded map[string]string) map[string]any {
	if !(decoded["security"] == "reality") {
		return nil
	}
	serverName := decoded["sni"]
	if serverName == "" {
		serverName = decoded["add"]
	}
	// alpn := []string{"h2", "http/1.1"}
	// if alpnlink, ok := decoded["alpn"]; ok && alpnlink != "" {
	// 	alpn = strings.Split(alpnlink, ",")
	// }

	fp := decoded["fp"]
	if fp == "" {
		// fp = "chrome"
	}

	return map[string]any{
		"serverName":  serverName,
		"fingerprint": fp,
		"shortId":     decoded["sid"],
		"spiderX":     decoded["spx"],
		"publicKey":   decoded["pbk"],
	}
}

func getMuxOptionsXray(decoded map[string]string) map[string]any {
	if decoded["mux"] == "" {
		return nil
	}
	return map[string]any{
		"enabled":     true,
		"concurrency": toInt(decoded["mux"]),
		// "xudpConcurrency": 16,
		// "xudpProxyUDP443": "reject"
	}
}
func getsplithttp(decoded map[string]string) map[string]any {
	path := decoded["path"]
	if path == "" {
		path = "/"
	}

	return map[string]any{
		"path": path,
		"host": decoded["host"],
		"headers": map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
		},
		// "maxUploadSize": 1000000,
		// "maxConcurrentUploads": 10
	}
}
func gethttpupgrade(decoded map[string]string) map[string]any {
	path := decoded["path"]
	if path == "" {
		path = "/"
	}

	return map[string]any{
		"path": path,
		"host": decoded["host"],
		"headers": map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
		},
	}
}
func getwebsocket(decoded map[string]string) map[string]any {
	path := decoded["path"]
	if path == "" {
		path = "/"
	}

	return map[string]any{
		"path": path,
		"host": decoded["host"],
		"headers": map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
		},
	}
}

func geth2(decoded map[string]string) map[string]any {
	path := decoded["path"]
	if path == "" {
		path = "/"
	}

	return map[string]any{
		"path": path,
		"host": strings.Split(decoded["host"], ","),
		"headers": map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
		},
	}
}

func getquic(decoded map[string]string) map[string]any {

	return map[string]any{
		"security": decoded["quicSecurity"],
		"key":      decoded["key"],
		"header": map[string]string{
			"type": decoded["headertype"],
		},
	}
}

func getgrpc(decoded map[string]string) map[string]any {

	return map[string]any{
		"authority":   decoded["authority"],
		"serviceName": decoded["servicename"],
		"mode":        decoded["mode"],
		"user_agent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
	}
}

func getStreamSettingsXray(decoded map[string]string) (map[string]any, error) {

	net, path := decoded["net"], decoded["path"]
	if net == "" {
		net = decoded["type"]
	}
	if path == "" {
		path = decoded["servicename"]
	}
	// fmoption.Printf("\n\nheaderType:%s, net:%s, type:%s\n\n", decoded["headerType"], net, decoded["type"])
	// if (decoded["type"] == "http" || decoded["headertype"] == "http") && net == "tcp" {
	// 	net = "http"
	// }
	res := map[string]any{}
	tls := getTLSOptionsXray(decoded)
	if tls != nil {
		res["security"] = "tls"
		res["tlsSettings"] = tls
	}
	reality := getRealityOptionsXray(decoded)
	if reality != nil {
		res["security"] = "reality"
		res["realitySettings"] = reality
	}
	res["network"] = net
	switch net {
	case "tcp":
		res[net+"Settings"] = map[string]any{}

	case "httpupgrade":
		res[net+"Settings"] = gethttpupgrade(decoded)
	case "ws":
		res[net+"Settings"] = getwebsocket(decoded)
	case "grpc":
		res[net+"Settings"] = getgrpc(decoded)
	case "quic":
		res[net+"Settings"] = getquic(decoded)
	case "splithttp":
		res[net+"Settings"] = getsplithttp(decoded)
	case "h2":
		res[net+"Settings"] = geth2(decoded)
	default:
		return nil, E.New("unknown transport type: " + net)
	}

	return res, nil
}
