package ray2sing

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"testing"

	T "github.com/sagernet/sing-box/option"
)

func CheckUrlAndJson(url string, expectedJSON string, t *testing.T) {
	configJson, err := Ray2Singbox(url)
	if err != nil {
		t.Fatalf("Error parsing URL: %v", err)
	}

	// Convert the expected JSON to a comparable Go structure
	expectedConfig, expectedPretty, err := json2map_prettystr(expectedJSON)
	if err != nil {
		t.Fatalf("Failed to unmarshal expected JSON: %v \n%v", err, expectedPretty)
	}
	config, configPretty, err := json2map_prettystr(configJson)
	if err != nil {
		t.Fatalf("Failed to unmarshal config JSON: %v \n%v", err, configPretty)
	}

	// Compare the actual options with the expected configuration
	if !reflect.DeepEqual(config, expectedConfig) {
		t.Errorf("Parsed options do not match expected configuration. Got \n%+v, \n\n =====want====\n%+v", configPretty, expectedPretty)
	}
}

func json2map_prettystr(injson string) ([]T.Outbound, string, error) {
	var conf T.Options
	if err := conf.UnmarshalJSON([]byte(injson)); err != nil {
		return conf.Outbounds, "", err
	}
	if len(conf.Outbounds) == 0 {
		return conf.Outbounds, "", fmt.Errorf("No outbound")
	}
	pp, err := json.MarshalIndent(conf.Outbounds, "", " ")
	if err != nil {
		return conf.Outbounds, "", err
	}
	return conf.Outbounds, string(pp), nil
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
