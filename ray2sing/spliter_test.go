package ray2sing

import (
	"reflect"
	"strings"
	"testing"
)

func trimmedSplit(text string) []string {
	parts := splitByPrefix(text)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func TestSplitByPrefixSeparator(t *testing.T) {
	for _, separator := range []string{"===", "#===", "  # ====  \r"} {
		got := trimmedSplit("[Interface]\nA = 1\n" + separator + "\nB = 2\n# comment\nC = 3")
		want := []string{"[Interface]\nA = 1", "B = 2\nC = 3"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("separator %q: got %q, want %q", separator, got, want)
		}
	}
	// "#" and "==" alone are only comments / text, not separators
	got := trimmedSplit("[Interface]\nA = 1\n#\nB == 2")
	if want := []string{"[Interface]\nA = 1\nB == 2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSplitByPrefixUnknownScheme(t *testing.T) {
	got := trimmedSplit("snell://psk@1.2.3.4:1?version=6#Snell\ntg://proxy?server=1.2.3.4&port=443&secret=abc\nvless://u@h:443?security=none#v")
	want := []string{
		"snell://psk@1.2.3.4:1?version=6#Snell",
		"tg://proxy?server=1.2.3.4&port=443&secret=abc",
		"vless://u@h:443?security=none#v",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
