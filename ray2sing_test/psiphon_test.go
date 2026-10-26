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
