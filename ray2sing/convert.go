package ray2sing

import (
	"fmt"
	"os"
	"runtime"

	"encoding/json"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var configTypes = map[string]ParserFunc{
	"vmess://":     VmessSingbox,
	"vless://":     VlessSingbox,
	"trojan://":    TrojanSingbox,
	"svmess://":    VmessSingbox,
	"svless://":    VlessSingbox,
	"strojan://":   TrojanSingbox,
	"ss://":        ShadowsocksSingbox,
	"tuic://":      TuicSingbox,
	"hysteria://":  HysteriaSingbox,
	"hysteria2://": Hysteria2Singbox,
	"hy2://":       Hysteria2Singbox,
	"ssh://":       SSHSingbox,
	"wg://":        WiregaurdSingbox,
	"wireguard://": WiregaurdSingbox,
	"ssconf://":    BeepassSingbox,
	"warp://":      WarpSingbox,
	"direct://":    DirectSingbox,
	"socks://":     SocksSingbox,
	"phttp://":     HttpSingbox,
	"phttps://":    HttpsSingbox,
	"http://":      HttpSingbox,
	"https://":     HttpsSingbox,
	"xvmess://":    VmessXray,
	"xvless://":    VlessXray,
	"xtrojan://":   TrojanXray,
	"xdirect://":   DirectXray,
}
var xrayConfigTypes = map[string]ParserFunc{
	"vmess://":  VmessXray,
	"vless://":  VlessXray,
	"trojan://": TrojanXray,
	"direct://": DirectXray,
}

func decodeUrlBase64IfNeeded(config string) string {
	splt := strings.SplitN(config, "://", 2)
    if len(splt)<2{
		//return config   
	}
	rest, _ := decodeBase64IfNeeded(splt[1])
	// fmt.Println(rest, err)
	return splt[0] + "://" + rest
}

func processSingleConfig(config string, useXrayWhenPossible bool) (outbound *T.Outbound, err error) {
	defer func() {
		if r := recover(); r != nil {
			outbound = nil
			stackTrace := make([]byte, 1024)
			s:=runtime.Stack(stackTrace, false)
			stackStr:=fmt.Sprint(string(stackTrace[:s]))
			err = E.New("Error in Parsing:", r, "Stack trace:", stackStr)
		}
	}()
	configDecoded := decodeUrlBase64IfNeeded(config)
	var configSingbox *T.Outbound
	if useXrayWhenPossible || strings.Contains(config, "&core=xray") || strings.Contains(configDecoded, "\"xhttp\"") || strings.Contains(config, "type=xhttp") {
		for k, v := range xrayConfigTypes {
			if strings.HasPrefix(config, k) {
				configSingbox, err = v(config)
			}
		}
	}
	if configSingbox == nil {
		for k, v := range configTypes {
			if strings.HasPrefix(config, k) {
				configSingbox, err = v(config)
			}
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

	// json.MarshalIndent(configSingbox, "", "  ")
	return configSingbox, nil
}
func GenerateConfigLite(input string, useXrayWhenPossible bool) (string, error) {

	configArray := strings.Split(strings.ReplaceAll(input, "\r", "\n"), "\n")

	var outbounds []T.Outbound
	counter := 0
	for _, config := range configArray {
		if len(config) < 5 || config[0] == '#' || config[0] == '/' {
			continue
		}
		detourTag := ""

		chains := strings.Split(config, "&&detour=")
		for _, chain1 := range chains {
			// fmt.Printf("%s", chain)
			chain, _ := decodeBase64IfNeeded(chain1)
			configSingbox, err := processSingleConfig(chain, useXrayWhenPossible)

			if err != nil {
				fmt.Fprintf(os.Stderr, "Error in %s \n %v\n", config, err)

				continue
			}
			configSingbox.Tag += " § " + strconv.Itoa(counter)

			var dialer *T.DialerOptions
			switch configSingbox.Type {
			case C.TypeWireGuard:
				dialer = &configSingbox.WireGuardOptions.DialerOptions
			case C.TypeVLESS:
				dialer = &configSingbox.VLESSOptions.DialerOptions
			case C.TypeVMess:
				dialer = &configSingbox.VMessOptions.DialerOptions
			case C.TypeDirect:
				dialer = &configSingbox.DirectOptions.DialerOptions
			case C.TypeTrojan:
				dialer = &configSingbox.TrojanOptions.DialerOptions
			case C.TypeHysteria:
				dialer = &configSingbox.HysteriaOptions.DialerOptions
			case C.TypeHysteria2:
				dialer = &configSingbox.Hysteria2Options.DialerOptions
			case C.TypeTUIC:
				dialer = &configSingbox.TUICOptions.DialerOptions
			case C.TypeSSH:
				dialer = &configSingbox.SSHOptions.DialerOptions
			case C.TypeShadowsocks:
				dialer = &configSingbox.ShadowsocksOptions.DialerOptions
			case C.TypeXray:
				dialer = &configSingbox.XrayOptions.DialerOptions
			default:
				dialer = nil
			}
			if dialer != nil {
				dialer.Detour = detourTag
			}
			if C.TypeCustom == configSingbox.Type {
				if warp, ok := configSingbox.CustomOptions["warp"].(map[string]interface{}); ok {
					warp["detour"] = detourTag
				}
			}
			detourTag = configSingbox.Tag

			outbounds = append(outbounds, *configSingbox)
			counter += 1

		}

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

func Ray2Singbox(configs string, useXrayWhenPossible bool) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = ""
			stackTrace := make([]byte, 1024)
			s:=runtime.Stack(stackTrace, false)
			stackStr:=fmt.Sprint(string(stackTrace[:s]))
			err = E.New("Error in Parsing", configs, r, "Stack trace:", stackStr)
			
			
		}
	}()

	configs, _ = decodeBase64IfNeeded(configs)

	convertedData, err := GenerateConfigLite(configs, useXrayWhenPossible)
	return convertedData, err
}
