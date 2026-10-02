package ray2sing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	T "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

func CheckUrlAndJson(url string, expectedJSON string, t *testing.T) {
	configJson, err := Ray2Singbox(libbox.BaseContext(nil), url, false)
	if err != nil {
		t.Fatalf("Error parsing URL: %v", err)
	}

	// Convert the expected JSON to a comparable Go structure
	expectedConfig, expectedPretty, err := json2map_prettystr(expectedJSON)
	if err != nil {
		t.Fatalf("Failed to unmarshal expected JSON: %v \n%v", err, expectedPretty)
	}
	config, configPretty, err := json2map_prettystr(string(configJson))
	if err != nil {
		t.Fatalf("Failed to unmarshal config JSON: %v \n%v", err, configPretty)
	}

	// Compare the actual options with the expected configuration
	if !reflect.DeepEqual(config, expectedConfig) {
		t.Errorf("Parsed options do not match expected configuration. Got \n%+v, \n\n =====want====\n%+v", configPretty, expectedPretty)
	}
}

type comparableOptions struct {
	Outbounds []T.Outbound `json:"outbounds,omitempty"`
	Endpoints []T.Endpoint `json:"endpoints,omitempty"`
}

func json2map_prettystr(injson string) (comparableOptions, string, error) {
	var conf T.Options
	ctx := libbox.BaseContext(nil)
	if err := conf.UnmarshalJSONContext(ctx, []byte(injson)); err != nil {
		return comparableOptions{}, "", err
	}
	out := comparableOptions{Outbounds: conf.Outbounds, Endpoints: conf.Endpoints}
	if len(out.Outbounds) == 0 && len(out.Endpoints) == 0 {
		return out, "", fmt.Errorf("No outbound")
	}
	raw, err := singjson.MarshalContext(ctx, out)
	if err != nil {
		return out, "", err
	}
	var pp bytes.Buffer
	if err := json.Indent(&pp, raw, "", " "); err != nil {
		return out, "", err
	}
	return out, pp.String(), nil
}

func sortedMarshal(data map[string]interface{}) (string, error) {
	// Create a slice for storing sorted keys
	var keys []string
	for k := range data {
		keys = append(keys, k)
	}

	// Sort the keys
	sort.Strings(keys)

	// Create a new map to hold sorted data
	sortedData := make(map[string]interface{}, len(data))
	for _, k := range keys {
		sortedData[k] = data[k]
	}

	// Marshal the sorted map with indentation
	jsonBytes, err := json.MarshalIndent(sortedData, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}
