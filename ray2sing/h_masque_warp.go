package ray2sing

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/cloudflare"
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// MasqueLinkSingbox converts a masque:// link. A link to Cloudflare's WARP is a warp endpoint
// with mode masque, since a masque outbound does not register WARP devices:
//
//   - with the link's device key, the endpoint uses that device (masque.device) until Cloudflare
//     refuses it, then a saved device of the endpoint or a registered one;
//   - without a key, a saved device or a registered one, as for any WARP config.
//
// A link is WARP when its endpoint is in WARP's ranges or under cloudflareclient.com, or its
// server name is Cloudflare's (or missing, which is Cloudflare's). A link to another MASQUE
// server stays a masque outbound, and needs its device key.
func MasqueLinkSingbox(link string) (*T.Outbound, *T.Endpoint, error) {
	out, err := MasqueSingbox(link)
	if err != nil {
		return nil, nil, err
	}
	options := out.Options.(*T.MASQUEOutboundOptions)
	if isWARPMasque(options) {
		return nil, masqueAsWARP(out.Tag, options), nil
	}
	if options.Device == nil || options.Device.PrivateKey == "" {
		return nil, nil, E.New("masque link to a server that is not WARP has no device key")
	}
	return out, nil, nil
}

func isWARPMasque(options *T.MASQUEOutboundOptions) bool {
	serverName := strings.ToLower(strings.TrimSpace(options.ServerName))
	if serverName == "" || cloudflare.IsWARPHost(serverName) {
		return true
	}
	if device := options.Device; device != nil {
		for _, endpoint := range []string{device.EndpointV4, device.EndpointV6, device.EndpointH2V4, device.EndpointH2V6} {
			if endpoint != "" && cloudflare.IsWARPHost(endpoint) {
				return true
			}
		}
	}
	return false
}

// masqueAsWARP is the warp endpoint of a masque:// link to WARP, with the link's settings.
func masqueAsWARP(tag string, options *T.MASQUEOutboundOptions) *T.Endpoint {
	device := options.Device
	warp := &T.WARPEndpointOptions{
		DialerOptions:    options.DialerOptions,
		UniqueIdentifier: masqueWARPIdentifier(options),
		Mode:             "masque",
		MTU:              options.MTU,
		UDPTimeout:       options.UDPTimeout,
		Scanner:          options.Scanner,
		MASQUE: &T.WARPMASQUEOptions{
			Enabled:              true,
			TLS:                  options.MASQUEOutboundTLSOptions,
			UseIPv6:              options.UseIPv6,
			UDPKeepalivePeriod:   options.UDPKeepalivePeriod,
			UDPInitialPacketSize: options.UDPInitialPacketSize,
			ReconnectDelay:       options.ReconnectDelay,
			VHTTP:                options.VHTTP,
			ServerName:           options.ServerName,
		},
	}
	if device != nil {
		warp.Profile.License = device.License
	}
	if device != nil && device.PrivateKey != "" {
		warp.MASQUE.Device = device
	} else if options.Scanner == nil || !options.Scanner.Enabled {
		// no device of its own: the link's endpoint is the server, unless the scanner looks for one
		warp.Server, warp.ServerPort = masqueLinkEndpoint(device)
	}
	if warp.MTU == 0 {
		warp.MTU = 1280 // a masque outbound's default; the warp endpoint's is WireGuard's
	}
	return &T.Endpoint{Type: C.TypeWARP, Tag: tag, Options: warp}
}

// masqueWARPIdentifier names the endpoint's devices and scores: the link's device id, else a
// hash of its key, else of its endpoints, so renaming the profile keeps them.
func masqueWARPIdentifier(options *T.MASQUEOutboundOptions) string {
	if options.UniqueIdentifier != "" {
		return options.UniqueIdentifier
	}
	device := options.Device
	if device == nil {
		return ""
	}
	if device.ID != "" {
		return device.ID
	}
	seed := device.PrivateKey
	if seed == "" {
		seed = strings.Join([]string{device.EndpointV4, device.EndpointV6, device.EndpointH2V4, device.EndpointH2V6, options.ServerName}, "|")
	}
	sum := sha256.Sum256([]byte(seed))
	return "masque-" + hex.EncodeToString(sum[:6])
}

// masqueLinkEndpoint is the first endpoint of the link, as a host and a port.
func masqueLinkEndpoint(device *T.MASQUEDeviceOptions) (string, uint16) {
	if device == nil {
		return "", 0
	}
	for _, endpoint := range []string{device.EndpointV4, device.EndpointV6, device.EndpointH2V4, device.EndpointH2V6} {
		if endpoint == "" {
			continue
		}
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			return strings.Trim(endpoint, "[]"), 443
		}
		value, _ := strconv.Atoi(port)
		if value <= 0 || value > 65535 {
			value = 443
		}
		return host, uint16(value)
	}
	return "", 0
}
