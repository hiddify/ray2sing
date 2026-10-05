package ray2sing

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/hiddify/finalmask"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	sjson "github.com/sagernet/sing/common/json"
)

var finalMaskQueryPattern = regexp.MustCompile(`[?&]fm=([^&#]*)`)

// finalMaskParam returns the Xray finalmask JSON of a link: the fm= query parameter
// (URL-encoded) or, for base64 vmess links, the "fm" key (a JSON string or object).
func finalMaskParam(config string) (string, error) {
	if match := finalMaskQueryPattern.FindStringSubmatch(config); match != nil {
		return url.QueryUnescape(match[1])
	}
	scheme, rest, ok := strings.Cut(config, "://")
	if !ok || scheme != "vmess" && scheme != "svmess" {
		return "", nil
	}
	decoded, err := decodeBase64FaultTolerant(rest)
	if err != nil {
		return "", nil
	}
	var data map[string]json.RawMessage
	if json.Unmarshal([]byte(decoded), &data) != nil {
		return "", nil
	}
	raw := data["fm"]
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return str, nil
	}
	if len(raw) > 0 && raw[0] == '{' {
		return string(raw), nil
	}
	return "", nil
}

func parseFinalMask(config string) (*T.FinalMaskOptions, error) {
	content, err := finalMaskParam(config)
	if err != nil {
		return nil, E.Cause(err, "decode fm")
	}
	if strings.TrimSpace(content) == "" {
		return nil, nil
	}
	var options T.FinalMaskOptions
	if err := sjson.Unmarshal([]byte(content), &options); err != nil {
		return nil, E.Cause(err, "parse fm")
	}
	if _, err := finalmask.Build(&options); err != nil {
		return nil, E.Cause(err, "fm")
	}
	if options.IsEmpty() {
		return nil, nil
	}
	return &options, nil
}

// applyFinalMask sets the link's fm= finalmask on the outbound/endpoint dialer.
func applyFinalMask(config string, outend *OutEnd) error {
	finalMask, err := parseFinalMask(config)
	if err != nil || finalMask == nil {
		return err
	}
	var options any
	if outend.outbound != nil {
		options = outend.outbound.Options
	} else if outend.endpoint != nil {
		options = outend.endpoint.Options
	}
	wrapper, ok := options.(T.DialerOptionsWrapper)
	if !ok {
		return E.New("fm: this config type has no dialer")
	}
	dialer := wrapper.TakeDialerOptions()
	dialer.FinalMask = finalMask
	wrapper.ReplaceDialerOptions(dialer)
	return nil
}
