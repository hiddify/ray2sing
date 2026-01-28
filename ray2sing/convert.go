package ray2sing

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
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
	if len(splt) < 2 {
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
			s := runtime.Stack(stackTrace, false)
			stackStr := fmt.Sprint(string(stackTrace[:s]))
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
func GenerateConfigLite(input string, useXrayWhenPossible bool) (*option.Options, error) {

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

			if dialerOpt, ok := configSingbox.Options.(T.DialerOptionsWrapper); ok {
				d := dialerOpt.TakeDialerOptions()
				d.Detour = detourTag
				dialerOpt.ReplaceDialerOptions(d)
			}

			if C.TypeCustom == configSingbox.Type {
				opts := configSingbox.Options.(map[string]any)
				if warp, ok := opts["warp"].(map[string]any); ok {
					warp["detour"] = detourTag
				}
			}
			detourTag = configSingbox.Tag

			outbounds = append(outbounds, *configSingbox)
			counter += 1

		}

	}
	if len(outbounds) == 0 {
		return nil, E.New("No outbounds found")
	}

	fullConfig := T.Options{
		Outbounds: outbounds,
	}

	return &fullConfig, nil
}

func Ray2Singbox(ctx context.Context, configs string, useXrayWhenPossible bool) (out []byte, err error) {
	convertedData, err := Ray2SingboxOptions(ctx, configs, useXrayWhenPossible)
	err = libbox.CheckConfigOptions(ctx, convertedData)
	if err != nil {
		return nil, err
	}
	return convertedData.MarshalJSONContext(ctx)
}
func Ray2SingboxOptions(ctx context.Context, configs string, useXrayWhenPossible bool) (out *option.Options, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			stackTrace := make([]byte, 1024)
			s := runtime.Stack(stackTrace, false)
			stackStr := fmt.Sprint(string(stackTrace[:s]))
			err = E.New("Error in Parsing", configs, r, "Stack trace:", stackStr)

		}
	}()

	configs, _ = decodeBase64IfNeeded(configs)

	convertedData, err := GenerateConfigLite(configs, useXrayWhenPossible)
	return convertedData, err
}
