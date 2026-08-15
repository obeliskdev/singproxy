package singproxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

var _ logger.Logger = nopLogger{}

type nopLogger struct{}

func (nopLogger) Trace(args ...any) {}
func (nopLogger) Debug(args ...any) {}
func (nopLogger) Info(args ...any)  {}
func (nopLogger) Warn(args ...any)  {}
func (nopLogger) Error(args ...any) {}
func (nopLogger) Fatal(args ...any) {}
func (nopLogger) Panic(args ...any) {}

func isXHTTPTransport(u *url.URL) bool {
	t := strings.ToLower(u.Query().Get("type"))
	return t == "xhttp" || t == "splithttp"
}

type xproxyProxy struct {
	original string
	proxyIP  net.IP
	typed    string
	cfg      Config
	xcfg     *xhttpConfig
	server   string
	port     int

	uuid       string
	password   string
	flow       string
	security   string
	alterID    int
	globalPad  bool
	authLength bool
}

func resolveProxyIP(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		return ips[0]
	}
	return nil
}

func newXHTTPProxy(originalURL string, u *url.URL, typed string, cfg Config) (*xproxyProxy, error) {
	if typed == "vmess" {
		return newXHTTPProxyVMess(originalURL, u, cfg)
	}

	params := u.Query()

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: xhttp: missing host", ErrInvalidProxyFormat)
	}
	port, err := parsePort(u.Port())
	if err != nil || port == 0 {
		return nil, fmt.Errorf("%w: xhttp: invalid or missing port", ErrInvalidProxyFormat)
	}

	xcfg, err := parseXHTTPTransportParams(params, host, int(port))
	if err != nil {
		return nil, fmt.Errorf("xhttp config: %w", err)
	}

	p := &xproxyProxy{
		original: originalURL,
		typed:    typed,
		cfg:      cfg,
		xcfg:     xcfg,
		server:   host,
		port:     int(port),
	}

	switch typed {
	case "vless":
		p.uuid = u.User.Username()
		p.flow = params.Get("flow")
	case "trojan":
		p.password = u.User.Username()
	case "shadowsocks":
		return nil, fmt.Errorf("xhttp: shadowsocks not supported with xhttp transport")
	default:
		return nil, fmt.Errorf("xhttp: protocol %s not supported with xhttp transport", typed)
	}

	p.proxyIP = resolveProxyIP(host)
	return p, nil
}

type vmessXHTTPConfig struct {
	uuid          string
	security      string
	alterID       int
	globalPadding bool
	authLength    bool
}

func extractVMessPayload(u *url.URL) (string, error) {
	if u.Opaque != "" {
		return u.Opaque, nil
	}
	if u.Host != "" {
		payload := u.Host
		if u.Path != "" {
			payload += u.Path
		}
		if u.ForceQuery || u.RawQuery != "" {
			payload += "?" + u.RawQuery
		}
		return payload, nil
	}
	return "", fmt.Errorf("unrecognized vmess URL format")
}

func decodeVMessJSON(payload string) (*vmessLinkData, error) {
	jsonBytes, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		jsonBytes, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			jsonBytes, err = base64.RawURLEncoding.DecodeString(payload)
			if err != nil {
				return nil, fmt.Errorf("failed to decode vmess data: %w", err)
			}
		}
	}
	var data vmessLinkData
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vmess JSON: %w", err)
	}
	return &data, nil
}

func parseVMessForXHTTP(u *url.URL) (*vmessXHTTPConfig, error) {
	payload, err := extractVMessPayload(u)
	if err != nil {
		return nil, err
	}
	data, err := decodeVMessJSON(payload)
	if err != nil {
		return nil, err
	}
	alterID, _ := parseAlterID(data.Aid)
	security := data.Security
	if security == "" {
		security = "auto"
	}
	return &vmessXHTTPConfig{
		uuid:          data.ID,
		security:      security,
		alterID:       alterID,
		globalPadding: data.GlobalPadding,
		authLength:    data.AuthLength,
	}, nil
}

func newXHTTPProxyVMess(originalURL string, u *url.URL, cfg Config) (*xproxyProxy, error) {
	vmCfg, err := parseVMessForXHTTP(u)
	if err != nil {
		return nil, fmt.Errorf("xhttp vmess: %w", err)
	}

	payload, err := extractVMessPayload(u)
	if err != nil {
		return nil, fmt.Errorf("xhttp vmess: %w", err)
	}
	data, err := decodeVMessJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("xhttp vmess: %w", err)
	}

	host := data.Add
	if host == "" {
		return nil, fmt.Errorf("%w: xhttp vmess: missing host in JSON", ErrInvalidProxyFormat)
	}
	port, err := parsePort(data.Port)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("%w: xhttp vmess: invalid or missing port in JSON", ErrInvalidProxyFormat)
	}

	params := url.Values{}
	params.Set("host", anyToString(data.Host))
	params.Set("path", anyToString(data.Path))
	params.Set("mode", "")
	if tlsStr := strings.ToLower(anyToString(data.TLS)); tlsStr == "tls" || strings.ToLower(data.Security) == "tls" {
		params.Set("security", "tls")
		params.Set("sni", anyToString(data.SNI))
		params.Set("alpn", anyToString(data.ALPN))
		params.Set("fp", anyToString(data.FP))
		params.Set("allowInsecure", anyToString(data.AllowInsecure))
	}

	xcfg, err := parseXHTTPTransportParams(params, host, int(port))
	if err != nil {
		return nil, fmt.Errorf("xhttp config: %w", err)
	}

	p := &xproxyProxy{
		original:   originalURL,
		typed:      "vmess",
		cfg:        cfg,
		xcfg:       xcfg,
		server:     host,
		port:       int(port),
		uuid:       vmCfg.uuid,
		security:   vmCfg.security,
		alterID:    vmCfg.alterID,
		globalPad:  vmCfg.globalPadding,
		authLength: vmCfg.authLength,
	}

	p.proxyIP = resolveProxyIP(host)
	return p, nil
}

func (p *xproxyProxy) String() string { return p.original }
func (p *xproxyProxy) Addr() net.IP   { return p.proxyIP }

func (p *xproxyProxy) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	if addr == "" {
		return nil, ErrMissingTarget
	}
	return p.dialSocksaddr(ctx, network, M.ParseSocksaddr(addr))
}

func (p *xproxyProxy) DialContextAddr(ctx context.Context, network string, addr *net.TCPAddr) (net.Conn, error) {
	if addr == nil {
		return nil, ErrMissingTarget
	}
	return p.dialSocksaddr(ctx, network, M.SocksaddrFromNet(addr))
}

func (p *xproxyProxy) dialSocksaddr(ctx context.Context, network string, targetAddr M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
	}

	dialCtx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()

	transportConn, err := dialXHTTP(dialCtx, p.xcfg, p.server, p.port, p.cfg)
	if err != nil {
		return nil, fmt.Errorf("xhttp transport: %w", err)
	}

	conn, err := p.wrapProtocolConn(transportConn, targetAddr)
	if err != nil {
		_ = transportConn.Close()
		return nil, err
	}
	return conn, nil
}

func (p *xproxyProxy) wrapProtocolConn(transportConn net.Conn, targetAddr M.Socksaddr) (net.Conn, error) {
	switch p.typed {
	case "vless":
		client, err := vless.NewClient(p.uuid, p.flow, nopLogger{})
		if err != nil {
			return nil, fmt.Errorf("xhttp vless client: %w", err)
		}
		conn, err := client.DialEarlyConn(transportConn, targetAddr)
		if err != nil {
			return nil, fmt.Errorf("xhttp vless dial: %w", err)
		}
		return conn, nil
	case "vmess":
		var opts []vmess.ClientOption
		if p.globalPad {
			opts = append(opts, vmess.ClientWithGlobalPadding())
		}
		if p.authLength {
			opts = append(opts, vmess.ClientWithAuthenticatedLength())
		}
		client, err := vmess.NewClient(p.uuid, p.security, p.alterID, opts...)
		if err != nil {
			return nil, fmt.Errorf("xhttp vmess client: %w", err)
		}
		return client.DialEarlyConn(transportConn, targetAddr), nil
	case "trojan":
		key := trojan.Key(p.password)
		return trojan.NewClientConn(transportConn, key, targetAddr), nil
	default:
		return nil, fmt.Errorf("xhttp: protocol %s not implemented", p.typed)
	}
}
