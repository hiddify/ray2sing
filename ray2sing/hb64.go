package ray2sing

import (
	"encoding/base64"
	"strings"
)

func looksLikeBase64(s string) bool {
	if len(s) < 4 {
		return false
	}
	valid := 0
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '+', r == '/', r == '-', r == '_', r == '=':
			valid++
		default:
			return false
		}
	}
	return valid >= len(s)-1 // tolerate 1–2 bad chars
}

// decodeBase64FaultTolerant tries many variants and returns the first successful decode.
// If none succeed it returns an error containing the debug attempts.
func decodeBase64FaultTolerant(raw string) (string, error) {

	raw = strings.TrimSpace(raw)
	if m := len(raw) % 4; m != 0 {
		raw += strings.Repeat("=", 4-m)
	}

	// Try URL-safe decoding
	data, err := base64.StdEncoding.DecodeString(raw)
	if err == nil {
		return string(data), nil
	}

	// Fallback to standard
	data, err = base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return raw, err
	}
	return string(data), nil
}
