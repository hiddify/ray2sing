package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestPsiphonRegion(t *testing.T) {
	for _, url := range []string{
		"psiphon://psiphon?region=DE#psiphon",
		"psiphon://psiphon?egress_region=DE#psiphon",
	} {
		expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "psiphon",
			"tag": "psiphon § 0",
			"egress_region": "DE"
		  }
		]
	  }
	`
		ray2sing.CheckUrlAndJson(url, expectedJSON, t)
	}
}

// A psiphon:// link shares the CDN edge scanner and its search.
func TestPsiphonScanner(t *testing.T) {
	url := "psiphon://auto?scan_sets=fastly,psiphon-akamai&scan_candidates=3&scan_timeout=2.5&search_timeout=2h&deep_concurrency=64&block_bits_ipv4=22#psiphon"
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "psiphon",
			"tag": "psiphon § 0",
			"scanner": {
			  "sets": ["fastly", "psiphon-akamai"],
			  "candidates": 3,
			  "timeout": "2.5s",
			  "search_timeout": "2h0m0s",
			  "deep_concurrency": 64,
			  "block_bits_ipv4": 22
			}
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
