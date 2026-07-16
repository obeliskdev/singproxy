package singproxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func parseShadowsocks(out *option.ShadowsocksOutboundOptions, u *url.URL) error {
	if u.Opaque != "" {
		decoded, decodeErr := base64Decode(u.Opaque)
		if decodeErr != nil {
			return fmt.Errorf("invalid ss base64 content: %w", decodeErr)
		}
		decodedStr := string(decoded)
		if strings.HasPrefix(decodedStr, "{") {
			return parseShadowsocksJSON(out, decodedStr)
		}
		newURL := "ss://" + decodedStr
		var err error
		u, err = url.Parse(newURL)
		if err != nil {
			return fmt.Errorf("failed to parse decoded ss url: %w", err)
		}
	} else if u.User == nil && u.Host != "" && !strings.Contains(u.Host, ":") {
		if decoded, err := base64Decode(u.Host); err == nil {
			decodedStr := string(decoded)
			if strings.HasPrefix(decodedStr, "{") {
				return parseShadowsocksJSON(out, decodedStr)
			}
			if strings.Contains(decodedStr, "@") {
				newURL := "ss://" + decodedStr
				if newU, err := url.Parse(newURL); err == nil {
					u = newU
				}
			}
		}
	}

	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("ss host/port invalid: %w", err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("invalid ss port: %w", err)
	}
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}

	var method, password string
	q := u.Query()

	if u.User != nil {
		userInfo := u.User.String()
		if decoded, err := base64Decode(userInfo); err == nil {
			decodedStr := string(decoded)
			if strings.HasPrefix(decodedStr, "ss://") {
				innerURL, err := url.Parse(decodedStr)
				if err == nil {
					if ih, ip, ie := net.SplitHostPort(innerURL.Host); ie == nil {
						host = ih
						port, _ = parsePort(ip)
						out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
					}
					if innerURL.User != nil {
						userInfo = innerURL.User.String()
						if d2, err := base64Decode(userInfo); err == nil {
							userInfo = string(d2)
						}
					}
				}
			}
			parts := strings.SplitN(decodedStr, ":", 2)
			if len(parts) == 2 {
				method, password = parts[0], parts[1]
				if strings.Count(password, ":") == 1 {
					password = strings.Split(password, ":")[0]
				}
			} else {
				method = u.User.Username()
				if p, ok := u.User.Password(); ok {
					password = p
				} else {
					password = method
					method = ""
				}
			}
		} else {
			method = u.User.Username()
			if p, ok := u.User.Password(); ok {
				password = p
			} else {
				password = method
				method = ""
			}
		}
	}

	if q.Get("encryption") == "none" {
		method = "none"
	} else if method == "" || len(method) > 40 {
		method = "aes-256-gcm"
	}

	out.Method = method
	out.Password = password

	if plugin := q.Get("plugin"); plugin != "" {
		parts := strings.SplitN(plugin, ";", 2)
		out.Plugin = parts[0]
		if len(parts) > 1 {
			out.PluginOptions = parts[1]
		}
	}

	if t := q.Get("type"); t != "" {
		if _, err := parseTransport(q, host); err != nil {
			return err
		}
	}

	return nil
}

type ssJSONConfig struct {
	Add           string `json:"add"`
	Port          any    `json:"port"`
	ID            string `json:"id"`
	Net           string `json:"net"`
	Type          any    `json:"type"`
	Host          any    `json:"host"`
	Path          any    `json:"path"`
	TLS           any    `json:"tls"`
	SNI           any    `json:"sni"`
	ALPN          any    `json:"alpn"`
	FP            any    `json:"fp"`
	Insecure      any    `json:"insecure"`
	AllowInsecure any    `json:"allowInsecure"`
	Password      string `json:"password"`
	Method        string `json:"method"`
	Encryption    string `json:"encryption"`
}

func (c *ssJSONConfig) str(field any) string {
	if field == nil {
		return ""
	}
	switch v := field.(type) {
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

func parseShadowsocksJSON(out *option.ShadowsocksOutboundOptions, jsonStr string) error {
	var cfg ssJSONConfig
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return fmt.Errorf("failed to parse ss JSON config: %w", err)
	}

	port, err := parsePort(cfg.Port)
	if err != nil {
		return fmt.Errorf("invalid ss json port: %w", err)
	}

	out.ServerOptions = option.ServerOptions{Server: cfg.Add, ServerPort: port}

	method := cfg.Method
	password := cfg.Password

	if method == "" {
		if cfg.Encryption == "none" {
			method = "none"
		} else if cfg.ID != "" && !strings.Contains(cfg.ID, ":") {
			method = "aes-256-gcm"
			password = cfg.ID
		}
	}

	if method == "" {
		return fmt.Errorf("ss JSON config missing method/password")
	}

	out.Method = method
	out.Password = password
	out.Network = option.NetworkList(strings.Join([]string{N.NetworkTCP, N.NetworkUDP}, "\n"))

	if netType := strings.ToLower(cfg.Net); netType != "" && netType != "tcp" && netType != "raw" {
		params := url.Values{}
		params.Set("type", netType)
		params.Set("host", cfg.str(cfg.Host))
		params.Set("path", cfg.str(cfg.Path))
		params.Set("sni", cfg.str(cfg.SNI))
		params.Set("alpn", cfg.str(cfg.ALPN))
		params.Set("fp", cfg.str(cfg.FP))
		if cfg.str(cfg.TLS) == "tls" {
			params.Set("security", "tls")
		}
		if cfg.str(cfg.Insecure) == "1" || cfg.str(cfg.Insecure) == "true" ||
			cfg.str(cfg.AllowInsecure) == "1" || cfg.str(cfg.AllowInsecure) == "true" {
			params.Set("insecure", "1")
		}
		if _, err := parseTransport(params, cfg.Add); err != nil {
			return err
		}
	}

	return nil
}

func parseShadowsocksR(out *option.ShadowsocksROutboundOptions, u *url.URL) error {
	var payload string
	if u.Opaque != "" {
		payload = u.Opaque
	} else {
		payload = u.Host
	}
	decoded, err := base64Decode(payload)
	if err != nil {
		return fmt.Errorf("failed to decode ssr data: %w", err)
	}
	decodedStr := string(decoded)
	if i := strings.Index(decodedStr, "?"); i != -1 {
		decodedStr = decodedStr[:i]
	}
	parts := strings.Split(decodedStr, ":")
	if len(parts) < 5 {
		return fmt.Errorf("invalid ssr link: expected at least 5 colon-separated fields, got %d", len(parts))
	}
	host := parts[0]
	port, err := parsePort(parts[1])
	if err != nil {
		return fmt.Errorf("invalid ssr port: %w", err)
	}
	protocol := parts[2]
	method := parts[3]
	obfs := parts[4]

	var password string
	if len(parts) >= 6 {
		if pw, err := base64Decode(parts[5]); err == nil {
			password = string(pw)
		}
	}

	var obfsParam, protocolParam string
	rawQuery := u.RawQuery
	if rawQuery != "" {
		params, err := url.ParseQuery(rawQuery)
		if err == nil {
			if v, err := base64Decode(params.Get("obfsparam")); err == nil {
				obfsParam = string(v)
			}
			if v, err := base64Decode(params.Get("protoparam")); err == nil {
				protocolParam = string(v)
			}
		}
	}

	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
	out.Method = method
	out.Password = password
	out.Obfs = obfs
	out.ObfsParam = obfsParam
	out.Protocol = protocol
	out.ProtocolParam = protocolParam
	out.Network = option.NetworkList(strings.Join([]string{N.NetworkTCP, N.NetworkUDP}, "\n"))
	return nil
}
