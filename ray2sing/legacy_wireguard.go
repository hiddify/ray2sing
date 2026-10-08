package ray2sing

// sing-box removed the legacy WireGuard outbound (local_address, peer_public_key, ...) in favour of
// the WireGuard endpoint; some panels still send it in sing-box JSON subscriptions.

// legacyWireGuardFields are the legacy outbound fields that have an endpoint equivalent; every
// other field (detour, bind_interface, ...) is a dialer field and is kept as it is.
var legacyWireGuardFields = map[string]bool{
	"type": true, "tag": true, "server": true, "server_port": true, "local_address": true,
	"private_key": true, "peer_public_key": true, "pre_shared_key": true, "reserved": true,
	"peers": true, "system_interface": true, "interface_name": true, "gso": true, "mtu": true,
	"workers": true, "network": true,
}

func isLegacyWireGuardOutbound(outbound map[string]any) bool {
	if outbound["type"] != "wireguard" {
		return false
	}
	_, hasLocalAddress := outbound["local_address"]
	_, hasPeerPublicKey := outbound["peer_public_key"]
	return hasLocalAddress || hasPeerPublicKey
}

// LegacyWireGuardOutboundToEndpoint converts a legacy WireGuard outbound into a WireGuard
// endpoint; ok is false when outbound is not a legacy WireGuard outbound.
func LegacyWireGuardOutboundToEndpoint(outbound map[string]any) (endpoint map[string]any, ok bool) {
	if !isLegacyWireGuardOutbound(outbound) {
		return nil, false
	}
	endpoint = map[string]any{"type": "wireguard"}
	for key, value := range outbound {
		if !legacyWireGuardFields[key] {
			endpoint[key] = value
		}
	}
	copyField := func(from, to string) {
		if value, exists := outbound[from]; exists {
			endpoint[to] = value
		}
	}
	copyField("tag", "tag")
	copyField("private_key", "private_key")
	copyField("mtu", "mtu")
	copyField("workers", "workers")
	copyField("system_interface", "system")
	copyField("interface_name", "name")
	switch address := outbound["local_address"].(type) {
	case string:
		endpoint["address"] = []any{address}
	case []any:
		endpoint["address"] = address
	}
	allIPs := []any{"0.0.0.0/0", "::/0"}
	peer := func(from map[string]any, publicKeyField string) map[string]any {
		converted := map[string]any{}
		set := func(key string, value any) {
			if value != nil {
				converted[key] = value
			}
		}
		set("address", from["server"])
		set("port", from["server_port"])
		set("public_key", from[publicKeyField])
		set("pre_shared_key", from["pre_shared_key"])
		set("reserved", from["reserved"])
		if allowed, exists := from["allowed_ips"]; exists {
			converted["allowed_ips"] = allowed
		} else {
			converted["allowed_ips"] = allIPs
		}
		return converted
	}
	var peers []any
	if legacyPeers, isList := outbound["peers"].([]any); isList && len(legacyPeers) > 0 {
		for _, item := range legacyPeers {
			if legacyPeer, isObject := item.(map[string]any); isObject {
				peers = append(peers, peer(legacyPeer, "public_key"))
			}
		}
	} else {
		peers = append(peers, peer(outbound, "peer_public_key"))
	}
	endpoint["peers"] = peers
	return endpoint, true
}

// MoveLegacyWireGuardOutbounds moves the legacy WireGuard outbounds of a sing-box JSON config
// into its endpoints, converted.
func MoveLegacyWireGuardOutbounds(outbounds, endpoints []any) ([]any, []any) {
	keptOutbounds := make([]any, 0, len(outbounds))
	for _, item := range outbounds {
		if outbound, isObject := item.(map[string]any); isObject {
			if endpoint, converted := LegacyWireGuardOutboundToEndpoint(outbound); converted {
				endpoints = append(endpoints, endpoint)
				continue
			}
		}
		keptOutbounds = append(keptOutbounds, item)
	}
	return keptOutbounds, endpoints
}
