package ray2sing

import (
	"encoding/json"
	"strings"

	T "github.com/sagernet/sing-box/option"

	// Mandatory features. Can't remove unless there are replacements.

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/common/errors"

	// // Default commander and all its services. This is an optional feature.
	// _ "github.com/xtls/xray-core/app/commander"
	// _ "github.com/xtls/xray-core/app/log/command"
	// _ "github.com/xtls/xray-core/app/proxyman/command"
	// _ "github.com/xtls/xray-core/app/stats/command"

	// // Developer preview services
	_ "github.com/xtls/xray-core/app/observatory/command"

	// Other optional features.
	_ "github.com/xtls/xray-core/app/dns"
	// _ "github.com/xtls/xray-core/app/dns/fakedns"
	_ "github.com/xtls/xray-core/app/log"
	// _ "github.com/xtls/xray-core/app/metrics"
	// _ "github.com/xtls/xray-core/app/policy"
	// _ "github.com/xtls/xray-core/app/reverse"
	// _ "github.com/xtls/xray-core/app/router"
	// _ "github.com/xtls/xray-core/app/stats"

	// // Fix dependency cycle caused by core import in internet package
	// _ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"

	// // Developer preview features
	_ "github.com/xtls/xray-core/app/observatory"

	// Inbound and outbound proxies.
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/dns"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/http"
	_ "github.com/xtls/xray-core/proxy/loopback"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"

	// _ "github.com/xtls/xray-core/proxy/wireguard"

	// Transports
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"

	// Transport headers
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/headers/srtp"
	_ "github.com/xtls/xray-core/transport/internet/headers/tls"
	_ "github.com/xtls/xray-core/transport/internet/headers/utp"
	_ "github.com/xtls/xray-core/transport/internet/headers/wechat"

	// _ "github.com/xtls/xray-core/transport/internet/headers/wireguard"

	// JSON & TOML & YAML
	_ "github.com/xtls/xray-core/main/json"
	// _ "github.com/xtls/xray-core/main/toml"
	// _ "github.com/xtls/xray-core/main/yaml"
	// // Load config from file or http(s)
	// _ "github.com/xtls/xray-core/main/confloader/external"
	// Commands
	// _ "github.com/xtls/xray-core/main/commands/all"
)

// func makeXrayOptions(decoded map[string]string, detour *conf.OutboundDetourConfig) (*T.Outbound, error) {
// 	config := strings.ReplaceAll(defaultXrayConfigStr, "proxy", detour.Tag)
// 	var defaultXrayConfig, err = readXrayConfig(config)
// 	if err != nil {
// 		return nil, err
// 	}
// 	uot := T.UDPOverTCPOptions{
// 		Enabled: true,
// 	}

// 	xray := T.Outbound{
// 		Type: "xray",
// 		Tag:  detour.Tag,
// 		XrayOptions: T.XrayOutboundOptions{
// 			UDPOverTCP: &uot,
// 			XConfig:    defaultXrayConfig,
// 		},
// 	}
// 	return &xray, nil
// }

// func readXrayConfig(jsonData string) (*conf.Config, error) {

// 	xrayConfig := conf.Config{}
// 	err := json.Unmarshal([]byte(jsonData), &xrayConfig)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &xrayConfig, nil
// }

func makeXrayOptions(decoded map[string]string, detour map[string]any) (*T.Outbound, error) {

	tag, _ := detour["tag"].(string) // Proper type assertion
	jsonConfig := strings.ReplaceAll(defaultXrayConfigStr, "proxy", tag)

	var xrayConfig map[string]interface{}
	err := json.Unmarshal([]byte(jsonConfig), &xrayConfig)
	if err != nil {
		return nil, err
	}

	if outbounds, ok := xrayConfig["outbounds"].([]interface{}); ok {
		// Append detour to the list of outbounds
		xrayConfig["outbounds"] = append([]interface{}{detour}, outbounds...)
	}
	uot := T.UDPOverTCPOptions{
		Enabled: true,
	}

	xray := T.Outbound{
		Type: "xray",
		Tag:  tag,
		XrayOptions: T.XrayOutboundOptions{
			UDPOverTCP: &uot,
			XConfig:    &xrayConfig,
		},
	}

	return &xray, nil
}

const defaultXrayConfigStr = `{
	  "log": {
		"loglevel": "warning", "dnsLog": false, "access": "none"
	  },
	  "dns": {
		"hosts": {
		  "dns.cloudflare.com": "cloudflare.com"
		},
		"servers": [
		  "https://dns.cloudflare.com/dns-query",
		  {"address": "localhost", "domains": ["full:cloudflare.com"]}
		],
		"tag": "dns-query",
		"disableFallback": true
	  },
	  "outbounds": [    
		{
		  "tag": "block",
		  "protocol": "blackhole"      
		},
		{
		  "tag": "direct",
		  "protocol": "freedom",      
		  "settings": {"domainStrategy": "ForceIP"}
		},
		{
		  "tag": "dns-out",
		  "protocol": "dns",      
		  "settings": {"nonIPQuery": "skip", "network": "tcp", "address": "1.1.1.1", "port": 53},
		  "streamSettings": {
			"sockopt": {
			  "dialerProxy": "chain1-fragment"
			}
		  }
		},
		{
		  "tag": "super-fragment",
		  "protocol": "freedom",
		  "settings": {
			"fragment": {
			  "packets": "tlshello",
			  "length": "6",
			  "interval": "0"
			}
		  },
		  "streamSettings": {
			"sockopt": {
			  "dialerProxy": "chain1-fragment"
			}
		  }            
		},
		{
		  "tag": "chain1-fragment",
		  "protocol": "freedom",
		  "settings": {
			"fragment": {
			  "packets": "1-3",
			  "length": "517",
			  "interval": "1"
			}
		  },
		  "streamSettings": {
			"sockopt": {
			  "dialerProxy": "chain2-fragment"
			}
		  }            
		},
		{
		  "tag": "chain2-fragment",
		  "protocol": "freedom",
		  "settings": {
			"domainStrategy": "ForceIP",
			"fragment": {
			  "packets": "1-1",
			  "length": "1",
			  "interval": "2"
			}
		  },
		  "streamSettings": {
			"sockopt": {
			  "tcpNoDelay": true
			}
		  }
		}     
	  ],
	  "routing": {
		"domainStrategy": "IPOnDemand",
		"rules": [                  
		  {"outboundTag": "chain1-fragment",  
		   "inboundTag": ["dns-query"]
		  },
		  {"outboundTag": "block",
		   "ip": ["10.10.34.0/24", "2001:4188:2:600:10:10:34:36", "2001:4188:2:600:10:10:34:35", "2001:4188:2:600:10:10:34:34"]
		  },
		  {"outboundTag": "proxy"}
		]
	  }
	}`
