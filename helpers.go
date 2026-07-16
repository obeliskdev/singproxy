package singproxy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
)

func parseAuth(auth string) (string, string) {
	decoded, err := base64Decode(auth)
	if err == nil {
		auth = string(decoded)
	}
	parts := strings.SplitN(auth, ":", 2)
	if len(parts) == 2 {
		unescapedUser, _ := url.PathUnescape(parts[0])
		unescapedPass, _ := url.PathUnescape(parts[1])
		return unescapedUser, unescapedPass
	}
	unescapedAuth, _ := url.PathUnescape(auth)
	return unescapedAuth, ""
}

func parsePort(p any) (uint16, error) {
	var portStr string
	switch v := p.(type) {
	case string:
		portStr = v
	case json.Number:
		portStr = v.String()
	case int, int16, int32, int64, uint, uint16, uint32, uint64:
		portStr = fmt.Sprintf("%d", v)
	case float64:
		if v == float64(int64(v)) {
			portStr = fmt.Sprintf("%d", int64(v))
		}
	}
	if portStr == "" {
		return 0, errors.New("port is missing or invalid")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port value '%s': %w", portStr, err)
	}
	return uint16(port), nil
}

func parseAlterID(aid any) (int, error) {
	if aid == nil {
		return 0, nil
	}
	aidStr := fmt.Sprintf("%v", aid)
	if f, err := strconv.ParseFloat(aidStr, 64); err == nil {
		return int(f), nil
	}
	return 0, errors.New("invalid alterId")
}

func parseBool(val any) bool {
	switch v := val.(type) {
	case string:
		b, _ := strconv.ParseBool(v)
		return b
	case bool:
		return v
	case int:
		return v > 0
	default:
		return false
	}
}

func parseNetIPPrefixList(prefixes string) ([]netip.Prefix, error) {
	if prefixes == "" {
		return nil, nil
	}
	parts := strings.Split(prefixes, ",")
	result := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			prefix, err := netip.ParsePrefix(trimmed)
			if err != nil {
				return nil, fmt.Errorf("invalid prefix '%s': %w", trimmed, err)
			}
			result = append(result, prefix)
		}
	}
	return result, nil
}

func base64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
	}
	return decoded, nil
}

func parseMultiplex(params url.Values, mux **option.OutboundMultiplexOptions) {
	muxVal := params.Get("mux")
	if muxVal == "" {
		return
	}
	opts := &option.OutboundMultiplexOptions{Enabled: true}
	if n, err := strconv.Atoi(muxVal); err == nil && n > 1 {
		opts.MaxStreams = n
	}
	*mux = opts
}
