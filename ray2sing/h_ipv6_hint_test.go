package ray2sing

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A link's ipv6 parameter declares the proxy's IPv6, and the declaration reaches the monitoring
// by the outbound's final tag; a link without it declares nothing.
func TestH_IPv6Hint(t *testing.T) {
	carried, declared := ipv6Hint("vless://id@1.2.3.4:443?security=tls&type=tcp&ipv6=1#a")
	require.True(t, declared && carried)
	carried, declared = ipv6Hint("trojan://p@1.2.3.4:443?ipv6=false#b")
	require.True(t, declared && !carried)
	_, declared = ipv6Hint("trojan://p@1.2.3.4:443?security=tls#c")
	require.False(t, declared)
	_, declared = ipv6Hint("not a url")
	require.False(t, declared)

	options, err := GenerateConfigLite("vless://6f9d4a9e-2d1c-4c7e-9a7b-3b2b0b6e1c11@1.2.3.4:443?security=none&type=tcp&encryption=none&ipv6=1#six\ntrojan://pass@1.2.3.4:443?security=tls&sni=a.com&type=tcp#plain", false)
	require.NoError(t, err)
	require.NotNil(t, options.Experimental)
	require.NotNil(t, options.Experimental.Monitoring)
	require.Equal(t, map[string]bool{"six § 0": true}, options.Experimental.Monitoring.IPv6Declared)

	options, err = GenerateConfigLite("trojan://pass@1.2.3.4:443?security=tls&sni=a.com&type=tcp#plain", false)
	require.NoError(t, err)
	require.Nil(t, options.Experimental, "nothing declared, nothing added")
}
