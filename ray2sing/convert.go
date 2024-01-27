package ray2sing

import (
	"fmt"
	"os"
	"runtime"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"encoding/json"
	"strconv"
	"strings"
)

var configTypes = map[string]ParserFunc{
	"vmess://":     VmessSingbox,
	"vless://":     VlessSingbox,
	"trojan://":    TrojanSingbox,
	"ss://":        ShadowsocksSingbox,
	"tuic://":      TuicSingbox,
	"hysteria://":  HysteriaSingbox,
	"hysteria2://": Hysteria2Singbox,
	"hy2://":       Hysteria2Singbox,
	"ssh://":       SSHSingbox,
	"wg://":        WiregaurdSingbox,
	"ssconf://":    BeepassSingbox,
	"warp://":      WarpSingbox,
	"direct://":    DirectSingbox,
}

func processSingleConfig(config string) (outbound *T.Outbound, err error) {
	defer func() {
		if r := recover(); r != nil {
			outbound = nil
			stackTrace := make([]byte, 1024)
			runtime.Stack(stackTrace, false)
			err = E.New("Error in Parsing:", r, "Stack trace:", stackTrace)
		}
	}()

	var configSingbox *T.Outbound
	for k, v := range configTypes {
		if strings.HasPrefix(config, k) {
			configSingbox, err = v(config)
		}
	}

	if err != nil {
		return nil, err
	}
	if configSingbox == nil {
		return nil, E.New("Not supported config type")
	}
	if configSingbox.Tag == "" {
		configSingbox.Tag = configSingbox.Type
	}
	json.MarshalIndent(configSingbox, "", "  ")
	return configSingbox, nil
}
func GenerateConfigLite(input string) (string, error) {

	configArray := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")

	var outbounds []T.Outbound
	for counter, config := range configArray {
		//
		configSingbox, err := processSingleConfig(config)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in %s \n %v\n", config, err)
			continue
		}
		configSingbox.Tag += " § " + strconv.Itoa(counter)
		outbounds = append(outbounds, *configSingbox)

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
			err = E.New("Error in Parsing", configs, r, "Stack trace:", stackTrace)
		}
	}()

	configs, _ = decodeBase64IfNeeded(configs)

	convertedData, err := GenerateConfigLite(configs)
	return convertedData, err
}
