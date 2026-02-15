package ray2sing

import (
	"regexp"
	"sort"
	"strings"
)

func buildRegex() *regexp.Regexp {
	prefixSet := map[string]struct{}{
		"#":  {},
		"//": {},
	}

	for k := range configTypes {
		prefixSet[k] = struct{}{}
	}
	for k := range endpointParsers {
		prefixSet[k] = struct{}{}
	}
	for k := range xrayConfigTypes {
		prefixSet[k] = struct{}{}
	}

	var prefixes []string
	for k := range prefixSet {
		prefixes = append(prefixes, ""+regexp.QuoteMeta(k))
	}

	// IMPORTANT: longest first
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i]) > len(prefixes[j])
	})

	// pattern := `(` + strings.Join(prefixes, "|") + `)`
	pattern := `(?m)^(?:` + strings.Join(prefixes, "|") + `)`

	return regexp.MustCompile(pattern)
}

var splitPattern = buildRegex()

func splitByPrefix(text string) []string {
	indexes := splitPattern.FindAllStringIndex(text, -1)

	if len(indexes) == 0 {
		return []string{text}
	}

	var result []string

	// Preserve header
	// if indexes[0][0] > 0 {
	// 	result = append(result, text[:indexes[0][0]])
	// }

	for i := 0; i < len(indexes); i++ {
		start := indexes[i][0]

		var end int
		if i+1 < len(indexes) {
			end = indexes[i+1][0]
		} else {
			end = len(text)
		}

		result = append(result, text[start:end])
	}

	return result
}
func expandDecodedConfig(configs string) []string {
	res := []string{}
	add := func(config ...string) {
		for _, c := range config {
			tc := strings.TrimSpace(c)
			if tc == "" || tc[0] == '#' || tc[0] == '/' {
				continue
			}
			res = append(res, tc)
		}
	}

	configs2 := []string{}
	for _, config := range strings.Split(configs, "\n") {
		configDecoded, err := decodeBase64IfNeeded(config)
		if err != nil {
			configDecoded = config
		}
		configs2 = append(configs2, strings.Split(strings.ReplaceAll(configDecoded, "\r", "\n"), "\n")...)
	}

	newConfigs := splitByPrefix(strings.Join(configs2, "\n"))

	add(newConfigs...)

	return res
}
