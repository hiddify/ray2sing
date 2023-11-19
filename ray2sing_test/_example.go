package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestBase(t *testing.T) {

	url := ""

	// Define the expected JSON structure
	expectedJSON := `
	
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
