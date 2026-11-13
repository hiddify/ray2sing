package ray2sing

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// aether:// links are the share links of Aether (github.com/CluvexStudio/Aether) profiles, as
// PattN, PattNG and the clients after them write them:
//
//	aether://[ip:port]?protocol=wg&scan=balanced&ip=v4&transport=h3&outer=ip:port&inner=ip:port#name
//
// A link carries no key: Aether registers its own WARP devices, so each hop becomes a warp://
// link, the warp endpoint registering a device the same way, and the link a chain of them:
//
//   - protocol=wg (the default): WireGuard, at the link's endpoint, or one the scanner finds.
//   - protocol=masque: MASQUE, over transport h3 (the default) or h2, at the link's endpoint.
//   - protocol=gool: WARP in WARP, WireGuard (inner) in WireGuard (outer).
//   - protocol=wg-over-masque: WireGuard (inner) carried in MASQUE (outer), Aether's gool.
//   - protocol=mim: MASQUE (inner) in MASQUE (outer).
//
// A hop without an endpoint is scanned for (the outer one) or takes its device's (the inner one).
// Other parameters:
//
//   - scan: turbo, balanced, thorough, verified (or stealth), ironclad; how far the scanner goes.
//   - ip: v4 (the default), v6 or both; v6 scans Cloudflare's IPv6 ranges and dials MASQUE over IPv6.
//   - noize: off turns noise off; the other profiles leave it to the endpoint's noise search.
//   - sni (the MASQUE server name, www.cloudflare.com as Aether's default) and fragment=1.
//   - psiphon (chain, reverse, only) with region, and tor (chain, reverse, only): chain carries
//     Psiphon or Tor inside WARP, reverse dials WARP through it (MASQUE over HTTP/2 then, which
//     needs a MASQUE protocol), only uses it alone. Tor runs without bridges.
//
// Aether's TLS fingerprint, ECH, DNS, exit country and Tor bridge settings have no counterpart in
// the warp endpoint and are ignored.

const aetherMasqueSNI = "www.cloudflare.com" // Aether's default, where the warp endpoint's is consumer-masque.cloudflareclient.com

type aetherHop struct {
	role     string // names the hop's device: wg, masque, inner-wg, inner-masque
	masque   bool
	endpoint string // host:port, or empty to scan for one or take the device's
	scan     bool   // the hop the network sees, which the scanner looks for
}

// expandAetherLink turns an aether:// link into its chain of links. A link that cannot be
// converted is left as it is, so AetherSingbox reports why.
func expandAetherLink(config string) string {
	if !strings.HasPrefix(strings.ToLower(config), "aether://") {
		return config
	}
	chain, err := aetherChain(config)
	if err != nil {
		return config
	}
	return chain
}

// AetherSingbox is reached for an aether:// link that expandAetherLink could not convert; it
// reports why.
func AetherSingbox(link string) (*T.Outbound, error) {
	if _, err := aetherChain(link); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("aether link stands for several outbounds and is read as a chain")
}

func aetherChain(link string) (string, error) {
	u, err := ParseUrl(link, 0)
	if err != nil {
		return "", err
	}
	param := func(key string) string { return strings.TrimSpace(u.Params[normalizeStr(key)]) }
	name := u.Name
	if name == "" {
		name = "Aether"
	}

	protocol := strings.ToLower(param("protocol"))
	if protocol == "" {
		protocol = "wg"
	}
	psiphon := aetherCarrierMode(param("psiphon"))
	tor := aetherCarrierMode(param("tor"))
	if (psiphon == "" && param("psiphon") != "") || (tor == "" && param("tor") != "") {
		return "", fmt.Errorf("aether link %q: unknown psiphon or tor mode", name)
	}
	if psiphon != "" && tor != "" && !(psiphon == "chain" && tor == "reverse" || psiphon == "reverse" && tor == "chain") {
		return "", fmt.Errorf("aether link %q: psiphon and tor go together only one inside the tunnel and the other around it", name)
	}

	var carriers struct{ inside, around, only []string }
	if psiphon != "" {
		query := url.Values{}
		if region := strings.ToUpper(param("region")); region != "" {
			query.Set("region", region)
		}
		psiphonLink := "psiphon://?" + query.Encode() + "#" + url.PathEscape(name)
		switch psiphon {
		case "chain":
			carriers.inside = append(carriers.inside, psiphonLink)
		case "reverse":
			carriers.around = append(carriers.around, psiphonLink)
		default:
			carriers.only = append(carriers.only, psiphonLink)
		}
	}
	if tor != "" {
		torLink := "tor://#" + url.PathEscape(name)
		switch tor {
		case "chain":
			carriers.inside = append(carriers.inside, torLink)
		case "reverse":
			carriers.around = append(carriers.around, torLink)
		default:
			carriers.only = append(carriers.only, torLink)
		}
	}
	if len(carriers.only) > 0 {
		if len(carriers.only) > 1 || len(carriers.inside)+len(carriers.around) > 0 {
			return "", fmt.Errorf("aether link %q: psiphon or tor alone goes with nothing else", name)
		}
		return carriers.only[0], nil
	}

	endpoint := ""
	if u.Hostname != "" && u.Port != 0 {
		endpoint = net.JoinHostPort(u.Hostname, strconv.Itoa(int(u.Port)))
	}
	outer, inner := aetherEndpoint(param("outer")), aetherEndpoint(param("inner"))
	var hops []aetherHop // the inner hop first, as a chain is written
	switch protocol {
	case "wg", "wireguard", "warp":
		hops = []aetherHop{{role: "wg", endpoint: endpoint, scan: true}}
	case "masque":
		hops = []aetherHop{{role: "masque", masque: true, endpoint: endpoint, scan: true}}
	case "gool", "gool-classic", "wiw", "warp-in-warp":
		if aetherSameHost(outer, inner) {
			inner = ""
		}
		hops = []aetherHop{{role: "inner-wg", endpoint: inner}, {role: "wg", endpoint: outer, scan: true}}
	case "wg-over-masque":
		hops = []aetherHop{{role: "inner-wg", endpoint: inner}, {role: "masque", masque: true, endpoint: outer, scan: true}}
	case "mim", "masque-in-masque":
		if aetherSameHost(outer, inner) {
			inner = ""
		}
		hops = []aetherHop{{role: "inner-masque", masque: true, endpoint: inner}, {role: "masque", masque: true, endpoint: outer, scan: true}}
	default:
		return "", fmt.Errorf("aether link %q: unknown protocol %q", name, protocol)
	}

	transport := strings.ToLower(param("transport"))
	if transport != "h2" {
		transport = "h3"
	}
	if len(carriers.around) > 0 {
		// Tor and Psiphon carry TCP alone: MASQUE goes over HTTP/2, and WireGuard cannot reach WARP
		if !hops[len(hops)-1].masque {
			return "", fmt.Errorf("aether link %q: WARP through psiphon or tor needs a MASQUE protocol", name)
		}
		transport = "h2"
	}
	ipv6 := strings.ToLower(param("ip")) == "v6" || param("ip") == "6"
	sni := param("sni")
	if sni == "" {
		sni = aetherMasqueSNI
	}
	noNoise := strings.ToLower(param("noize")) == "off"
	identity := aetherIdentity(link)

	links := append([]string{}, carriers.inside...)
	for _, hop := range hops {
		query := url.Values{}
		if hop.masque {
			query.Set("mode", "masque")
			query.Set("vhttp", transport)
			query.Set("masque_sni", sni)
			if ipv6 {
				query.Set("masque_ipv6", "1")
			}
			if param("fragment") == "1" {
				query.Set("fragment", "1")
			}
		} else {
			query.Set("mode", "wg")
			if noNoise {
				query.Set("search_noise", "0")
			}
		}
		if hop.scan && hop.endpoint == "" {
			aetherScanParams(query, strings.ToLower(param("scan")), ipv6, hop.masque)
		}
		server := "auto"
		if hop.endpoint != "" {
			server = hop.endpoint
		}
		warp := url.URL{Scheme: "warp", User: url.User(identity + "-" + hop.role), Host: server, RawQuery: query.Encode(), Fragment: name}
		links = append(links, warp.String())
	}
	links = append(links, carriers.around...)
	return strings.Join(links, " -> "), nil
}

// aetherCarrierMode is chain, reverse or only for a psiphon or tor value; empty for off or an unknown one.
func aetherCarrierMode(value string) string {
	switch strings.ToLower(value) {
	case "chain", "reverse", "only":
		return strings.ToLower(value)
	}
	return ""
}

// aetherEndpoint is an outer or inner hop, host:port, or empty when it is not one: Aether requires the port.
func aetherEndpoint(value string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || host == "" {
		return ""
	}
	if number, err := strconv.Atoi(port); err != nil || number <= 0 || number > 65535 {
		return ""
	}
	return net.JoinHostPort(host, port)
}

// aetherSameHost reports whether both hops are on one address, which Aether refuses for WARP in
// WARP and MASQUE in MASQUE: the inner hop is then left to the device.
func aetherSameHost(outer, inner string) bool {
	if outer == "" || inner == "" {
		return false
	}
	outerHost, _, _ := net.SplitHostPort(outer)
	innerHost, _, _ := net.SplitHostPort(inner)
	return outerHost == innerHost
}

// aetherScanParams sets the scanner of the hop the network sees after Aether's scan mode and IP version.
func aetherScanParams(query url.Values, mode string, ipv6, masque bool) {
	switch mode {
	case "turbo":
		query.Set("scan_count", "16")
	case "thorough":
		query.Set("scan_count", "256")
	case "ironclad":
		query.Set("max_rtt", "2s")
	}
	if ipv6 {
		if masque {
			query.Set("scan_cidrs", "2606:4700:103::/64")
		} else {
			query.Set("scan_cidrs", "2606:4700:d0::/64,2606:4700:d1::/64")
		}
	}
}

// aetherIdentity names the devices of a link, from its settings without its name, so renaming or
// moving the link in a subscription keeps its devices.
func aetherIdentity(link string) string {
	if i := strings.IndexByte(link, '#'); i >= 0 {
		link = link[:i]
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(link)))
	return "aether-" + hex.EncodeToString(sum[:6])
}
