package ray2sing

import (
	"fmt"
	"strconv"

	T "github.com/sagernet/sing-box/option"

	"encoding/base64"
	"encoding/json"
)

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

func VmessSingbox(vmessURL string) (*T.Outbound, error) {
	decoded, err := decodeVmess(vmessURL)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("port:%v", decoded["port"])
	port := toInt16(decoded["port"])
	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}
	security := "auto"
	if decoded["scy"] != "" {
		security = decoded["scy"]
	}
	return &T.Outbound{
		Tag:  decoded["ps"],
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
