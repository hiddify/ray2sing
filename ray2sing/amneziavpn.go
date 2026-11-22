package ray2sing

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// AmneziaVPN share links: vpn://<base64url payload>. AmneziaVPN writes the payload as its JSON
// server config compressed with Qt's qCompress (a 4-byte big-endian length, then a zlib stream);
// 3x-ui writes the AmneziaWG client .conf text itself, uncompressed. AmneziaVPN reads both.

// maxAmneziaVPNPayload bounds what a link may decompress to: a server config is a few kilobytes.
const maxAmneziaVPNPayload = 1 << 20

// AmneziaVPNSingbox reads a vpn:// link that carries an AmneziaWG or WireGuard config.
func AmneziaVPNSingbox(link string) (*T.Endpoint, error) {
	rest := strings.TrimPrefix(link, "vpn://")
	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	payload, err := decodeBase64FaultTolerant(strings.TrimSpace(rest))
	if err != nil {
		return nil, fmt.Errorf("vpn link: the payload is not base64: %w", err)
	}
	data := []byte(payload)
	if uncompressed, err := qUncompress(data); err == nil {
		data = uncompressed
	}
	conf, description, err := amneziaVPNConf(data)
	if err != nil {
		return nil, err
	}
	endpoint, err := AWGSingboxTxt(conf)
	if err != nil {
		return nil, fmt.Errorf("vpn link: %w", err)
	}
	if name == "" && !confHasName(conf) {
		name = description
		if name == "" {
			name = confPeerRemark(conf)
		}
	}
	if name = strings.TrimSpace(name); name != "" {
		endpoint.Tag = name
	}
	return endpoint, nil
}

// qUncompress reverses Qt's qCompress: the uncompressed size as 4 big-endian bytes, then zlib.
func qUncompress(data []byte) ([]byte, error) {
	if len(data) < 6 {
		return nil, errors.New("too short")
	}
	size := binary.BigEndian.Uint32(data[:4])
	if size > maxAmneziaVPNPayload {
		return nil, fmt.Errorf("uncompressed size %d is too large", size)
	}
	reader, err := zlib.NewReader(bytes.NewReader(data[4:]))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	out, err := io.ReadAll(io.LimitReader(reader, int64(size)+1))
	if err != nil {
		return nil, err
	}
	if len(out) != int(size) {
		return nil, fmt.Errorf("uncompressed %d bytes, the header says %d", len(out), size)
	}
	return out, nil
}

// amneziaVPNConf returns the WireGuard .conf text a payload carries, and the server's
// description when the payload is AmneziaVPN's JSON.
func amneziaVPNConf(data []byte) (conf, description string, err error) {
	text := strings.TrimSpace(string(data))
	if strings.Contains(text, "[Interface]") && !strings.HasPrefix(text, "{") {
		return text, "", nil
	}
	var server struct {
		Containers       []map[string]json.RawMessage `json:"containers"`
		DefaultContainer string                       `json:"defaultContainer"`
		Description      string                       `json:"description"`
	}
	if err := json.Unmarshal([]byte(text), &server); err != nil {
		return "", "", errors.New("vpn link: neither a WireGuard config nor an AmneziaVPN config")
	}
	// the default container first, then the others in their order
	containers := make([]map[string]json.RawMessage, 0, len(server.Containers))
	for _, container := range server.Containers {
		if containerName(container) == server.DefaultContainer {
			containers = append([]map[string]json.RawMessage{container}, containers...)
		} else {
			containers = append(containers, container)
		}
	}
	for _, container := range containers {
		for _, value := range container {
			// {"awg": {"last_config": "{\"config\": \"[Interface]...\"}"}}: the protocol's
			// client config, a JSON string inside the JSON
			var protocol struct {
				LastConfig string `json:"last_config"`
			}
			if json.Unmarshal(value, &protocol) != nil || protocol.LastConfig == "" {
				continue
			}
			var last struct {
				Config string `json:"config"`
			}
			if json.Unmarshal([]byte(protocol.LastConfig), &last) != nil {
				continue
			}
			if strings.Contains(last.Config, "[Interface]") {
				return last.Config, server.Description, nil
			}
		}
	}
	return "", "", errors.New("vpn link: the AmneziaVPN config has no AmneziaWG or WireGuard client config")
}

func containerName(container map[string]json.RawMessage) string {
	var name string
	_ = json.Unmarshal(container["container"], &name)
	return name
}

// confHasName reports whether a conf names itself with a "Name =" line in [Interface], which
// AWGSingboxTxt uses as the tag.
func confHasName(conf string) bool {
	for _, line := range strings.Split(conf, "\n") {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(key) == "Name" {
			return true
		}
	}
	return false
}

// confPeerRemark returns the "# <remark>" comment right before [Peer], where 3x-ui writes the
// config's remark.
func confPeerRemark(conf string) string {
	lines := strings.Split(conf, "\n")
	for i, line := range lines {
		if !strings.EqualFold(strings.TrimSpace(line), "[Peer]") {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			previous := strings.TrimSpace(lines[j])
			if previous == "" {
				continue
			}
			if remark, ok := strings.CutPrefix(previous, "#"); ok {
				return strings.TrimSpace(remark)
			}
			return ""
		}
		return ""
	}
	return ""
}
