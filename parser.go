package singproxy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

var (
	ErrInvalidProxyFormat      = errors.New("invalid proxy format")
	ErrUnsupportedScheme       = errors.New("unsupported proxy scheme")
	ErrMissingTarget           = errors.New("missing target")
	ErrProxyDialTimeoutReached = &net.OpError{
		Op:  "dial",
		Net: "proxy dial timeout",
		Err: errors.New("proxy dial timed out"),
	}
)

type vmessLinkData struct {
	V               string `json:"v"`
	PS              string `json:"ps"`
	Add             string `json:"add"`
	Port            any    `json:"port"`
	ID              string `json:"id"`
	Aid             any    `json:"aid"`
	Net             string `json:"net"`
	Type            string `json:"type"`
	Host            string `json:"host"`
	Path            string `json:"path"`
	TLS             string `json:"tls"`
	SNI             string `json:"sni"`
	ALPN            string `json:"alpn"`
	FP              string `json:"fp"`
	AllowInsecure   any    `json:"allowInsecure"`
	Security        string `json:"security"`
	PacketEncoding  string `json:"packet_encoding"`
	GlobalPadding   bool   `json:"global_padding"`
	AuthLength      bool   `json:"authenticated_length"`
	ServiceNameGRPC string `json:"serviceName"`
}

func getProxyType(scheme string) (string, error) {
	switch strings.ToLower(scheme) {
	case "vmess":
		return "vmess", nil
	case "http", "https", "http2":
		return "http", nil
	case "vless":
		return "vless", nil
	case "trojan", "trojan-go":
		return "trojan", nil
	case "ss", "shadowsocks":
		return "shadowsocks", nil
	case "tuic":
		return "tuic", nil
	case "hy", "hysteria":
		return "hysteria", nil
	case "hy2", "hysteria2":
		return "hysteria2", nil
	case "ssh":
		return "ssh", nil
	case "socks", "socks5", "socks4":
		return "socks", nil
	case "wireguard":
		return "wireguard", nil
	case "direct":
		return "direct", nil
	case "tor":
		return "tor", nil
	case "anytls", "atls":
		return "anytls", nil
	case "shadowtls":
		return "shadowtls", nil
	case "naive", "naive+https":
		return "naive", nil
	default:
		return "", fmt.Errorf("%w: unknown scheme %s", ErrUnsupportedScheme, scheme)
	}
}

func parseProxyURL(out any, u *url.URL, typed string, timeout time.Duration) (err error) {
	dialerOptions := option.DialerOptions{
		ReuseAddr:      true,
		ConnectTimeout: badoption.Duration(timeout),
	}
	switch typed {
	case "vmess":
		options := out.(*option.VMessOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseVMess(options, u)
	case "http":
		options := out.(*option.HTTPOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseHTTP(options, u)
	case "vless":
		options := out.(*option.VLESSOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseVLESS(options, u)
	case "trojan":
		options := out.(*option.TrojanOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseTrojan(options, u)
	case "shadowsocks":
		options := out.(*option.ShadowsocksOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseShadowsocks(options, u)
	case "tuic":
		options := out.(*option.TUICOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseTUIC(options, u)
	case "hysteria":
		options := out.(*option.HysteriaOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseHysteria(options, u)
	case "hysteria2":
		options := out.(*option.Hysteria2OutboundOptions)
		options.DialerOptions = dialerOptions
		return parseHysteria2(options, u)
	case "ssh":
		options := out.(*option.SSHOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseSSH(options, u)
	case "socks":
		options := out.(*option.SOCKSOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseSOCKS(options, u)
	case "wireguard":
		options := out.(*option.LegacyWireGuardOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseWireGuard(options, u)
	case "shadowtls":
		options := out.(*option.ShadowTLSOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseShadowTLS(options, u)
	case "anytls":
		options := out.(*option.AnyTLSOutboundOptions)
		options.DialerOptions = dialerOptions
		return parseAnyTLS(options, u)
	case "direct", "tor":
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedScheme, typed)
	}
}

func parseShadowsocks(out *option.ShadowsocksOutboundOptions, u *url.URL) error {
	if u.Host == "" && u.Opaque != "" {
		decoded, decodeErr := base64Decode(u.Opaque)
		if decodeErr != nil {
			return fmt.Errorf("invalid ss base64 content: %w", decodeErr)
		}
		newURL := "ss://" + string(decoded)
		var err error
		u, err = url.Parse(newURL)
		if err != nil {
			return fmt.Errorf("failed to parse decoded ss url: %w", err)
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
		if decoded, err := base64Decode(u.User.String()); err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				method, password = parts[0], parts[1]
				if strings.Count(password, ":") == 1 {
					password = strings.Split(password, ":")[0]
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
	return nil
}

func parseWireGuard(out *option.LegacyWireGuardOutboundOptions, u *url.URL) error {
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("wireguard host/port invalid: %w", err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("invalid wireguard port: %w", err)
	}
	params := u.Query()
	localAddressesStr := strings.Join(params["address"], ",")
	localAddr, err := parseNetIPPrefixList(localAddressesStr)
	if err != nil {
		return fmt.Errorf("invalid wireguard address: %w", err)
	}
	mtu, _ := strconv.ParseUint(params.Get("mtu"), 10, 32)
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
	unescapedKey, _ := url.PathUnescape(u.User.Username())
	out.PrivateKey = unescapedKey
	out.PeerPublicKey, _ = url.PathUnescape(params.Get("publickey"))
	out.PreSharedKey = params.Get("presharedkey")
	out.LocalAddress = localAddr
	out.MTU = uint32(mtu)
	return nil
}

func parseHTTP(out *option.HTTPOutboundOptions, u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return errors.New("http proxy host is empty")
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return fmt.Errorf("invalid http port: %w", err)
	}
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
	out.Path = u.Path
	if u.User != nil {
		username, password := parseAuth(u.User.String())
		out.Username = username
		out.Password = password
	}
	params := u.Query()
	parseTLS(params, &out.OutboundTLSOptionsContainer, host)
	if strings.EqualFold(u.Scheme, "https") && out.TLS == nil {
		out.TLS = &option.OutboundTLSOptions{Enabled: true, ServerName: host}
	}
	if strings.EqualFold(u.Scheme, "http2") {
		if out.TLS == nil {
			out.TLS = &option.OutboundTLSOptions{Enabled: true, ServerName: host}
		}
		out.TLS.ALPN = append(out.TLS.ALPN, "h2")
	}
	return nil
}

func parseSOCKS(out *option.SOCKSOutboundOptions, u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return errors.New("socks proxy host is empty")
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return fmt.Errorf("invalid socks port: %w", err)
	}
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
	out.Version = "5"
	if strings.Contains(u.Scheme, "4") {
		out.Version = "4"
	}
	if u.User != nil {
		username, password := parseAuth(u.User.String())
		out.Username = username
		out.Password = password
	}
	return nil
}

func parseVMess(out *option.VMessOutboundOptions, u *url.URL) error {
	var payload string
	if u.Opaque != "" {
		payload = u.Opaque
	} else if u.Host != "" && u.User == nil {
		payload = u.Host
	} else {
		return errors.New("unrecognized vmess URL format")
	}
	return parseVMessBase64(out, payload)
}

func parseVMessBase64(out *option.VMessOutboundOptions, b64 string) error {
	jsonBytes, err := base64Decode(b64)
	if err != nil {
		return fmt.Errorf("failed to decode vmess data: %w", err)
	}
	var data vmessLinkData
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return fmt.Errorf("failed to unmarshal vmess JSON: %w", err)
	}
	port, err := parsePort(data.Port)
	if err != nil {
		return fmt.Errorf("invalid vmess port: %w", err)
	}
	alterID, _ := parseAlterID(data.Aid)
	out.ServerOptions = option.ServerOptions{Server: data.Add, ServerPort: port}
	out.UUID = data.ID
	out.Security = "auto"
	if data.Security != "" {
		out.Security = data.Security
	}
	out.AlterId = alterID
	out.GlobalPadding = data.GlobalPadding
	out.AuthenticatedLength = data.AuthLength
	out.Network = option.NetworkList(strings.Join([]string{N.NetworkTCP, N.NetworkUDP}, "\n"))
	out.PacketEncoding = data.PacketEncoding
	if networkType := strings.ToLower(data.Net); networkType != "tcp" && networkType != "" && networkType != "raw" {
		transport := &option.V2RayTransportOptions{Type: networkType}
		switch transport.Type {
		case "ws":
			transport.WebsocketOptions.Path = data.Path
			if data.Host != "" {
				transport.WebsocketOptions.Headers = badoption.HTTPHeader{"Host": {data.Host}}
			}
		case "grpc":
			transport.GRPCOptions.ServiceName = data.ServiceNameGRPC
			if transport.GRPCOptions.ServiceName == "" {
				transport.GRPCOptions.ServiceName = data.Path
			}
		case "httpupgrade":
			transport.HTTPUpgradeOptions.Host = data.Host
			transport.HTTPUpgradeOptions.Path = data.Path
			if data.Host != "" {
				transport.HTTPUpgradeOptions.Headers = badoption.HTTPHeader{"Host": {data.Host}}
			}
		default:
			return fmt.Errorf("unsupported vmess network: %s", transport.Type)
		}
		out.Transport = transport
	}
	tlsType := strings.ToLower(data.TLS)
	if tlsType == "" && strings.ToLower(data.Security) == "tls" {
		tlsType = "tls"
	}
	if tlsType == "tls" {
		out.TLS = new(option.OutboundTLSOptions)
		params := url.Values{}
		params.Set("sni", data.SNI)
		if data.Host != "" && data.SNI == "" {
			params.Set("sni", data.Host)
		}
		params.Set("allowInsecure", fmt.Sprintf("%v", data.AllowInsecure))
		params.Set("alpn", data.ALPN)
		params.Set("fp", data.FP)
		params.Set("security", "tls")
		parseTLS(params, &out.OutboundTLSOptionsContainer, data.Add)
	}
	return nil
}

func parseVLESS(out *option.VLESSOutboundOptions, u *url.URL) error {
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("vless host/port invalid: %w", err)
	}
	port16, err := parsePort(port)
	if err != nil {
		return fmt.Errorf("invalid vless port: %w", err)
	}
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port16}
	out.UUID = u.User.Username()
	out.Flow = u.Query().Get("flow")
	out.Network = option.NetworkList(strings.Join([]string{N.NetworkTCP, N.NetworkUDP}, "\n"))
	params := u.Query()
	if transport, err := parseTransport(params, host); err == nil {
		out.Transport = transport
	} else {
		return err
	}
	parseTLS(params, &out.OutboundTLSOptionsContainer, host)
	if pe := params.Get("packetEncoding"); pe == "xudp" {
		out.PacketEncoding = &pe
	}
	return nil
}

func parseTrojan(out *option.TrojanOutboundOptions, u *url.URL) error {
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("trojan host/port invalid: %w", err)
	}
	port16, err := parsePort(port)
	if err != nil {
		return fmt.Errorf("invalid trojan port: %w", err)
	}
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port16}
	if pass, ok := u.User.Password(); ok {
		out.Password = pass
	} else {
		out.Password = u.User.Username()
	}
	out.Network = option.NetworkList(strings.Join([]string{N.NetworkTCP, N.NetworkUDP}, "\n"))
	out.TLS = new(option.OutboundTLSOptions)
	params := u.Query()
	if transport, err := parseTransport(params, host); err == nil {
		out.Transport = transport
	} else {
		return err
	}
	parseTLS(params, &out.OutboundTLSOptionsContainer, host)
	return nil
}

func parseTUIC(out *option.TUICOutboundOptions, u *url.URL) error {
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("tuic host/port invalid: %w", err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("invalid tuic port: %w", err)
	}
	params := u.Query()
	uuid, password := u.User.Username(), params.Get("password")
	if p, ok := u.User.Password(); ok {
		password = p
	}
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
	out.UUID = uuid
	out.Password = password
	out.CongestionControl = params.Get("congestion_control")
	out.UDPRelayMode = params.Get("udp_relay_mode")
	out.Network = N.NetworkUDP
	sni := params.Get("sni")
	if sni == "" {
		sni = host
	}
	alpn := strings.Split(params.Get("alpn"), ",")
	insecure := parseBool(params.Get("insecure")) || parseBool(params.Get("allow_insecure"))
	disableSNI := parseBool(params.Get("disable_sni"))
	out.TLS = &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: sni,
		Insecure:   insecure,
		DisableSNI: disableSNI,
		ALPN:       alpn,
	}
	return nil
}

func parseHysteria(out *option.HysteriaOutboundOptions, u *url.URL) error {
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("hysteria host/port invalid: %w", err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("invalid hysteria port: %w", err)
	}
	params := u.Query()
	up, _ := strconv.Atoi(params.Get("upmbps"))
	down, _ := strconv.Atoi(params.Get("downmbps"))
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
	out.AuthString = u.User.Username()
	out.UpMbps = up
	out.DownMbps = down
	out.Obfs = params.Get("obfs")
	out.Network = N.NetworkUDP
	sni := params.Get("peer")
	if sni == "" {
		sni = params.Get("sni")
	}
	if sni == "" {
		sni = host
	}
	out.TLS = &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: sni,
		Insecure:   parseBool(params.Get("insecure")),
		ALPN:       strings.Split(params.Get("alpn"), ","),
	}
	return nil
}

func parseHysteria2(out *option.Hysteria2OutboundOptions, u *url.URL) error {
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("hysteria2 host/port invalid: %w", err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("invalid hysteria2 port: %w", err)
	}
	params := u.Query()
	up, _ := strconv.Atoi(params.Get("upmbps"))
	down, _ := strconv.Atoi(params.Get("downmbps"))
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
	out.Password = u.User.Username()
	out.UpMbps = up
	out.DownMbps = down
	out.Network = N.NetworkUDP
	if obfsType := params.Get("obfs"); obfsType != "" {
		out.Obfs = &option.Hysteria2Obfs{
			Type:     obfsType,
			Password: params.Get("obfs-password"),
		}
	}
	sni := params.Get("sni")
	if sni == "" {
		sni = host
	}
	out.TLS = &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: sni,
		Insecure:   parseBool(params.Get("insecure")) || parseBool(params.Get("allowInsecure")),
		ALPN:       strings.Split(params.Get("alpn"), ","),
	}
	return nil
}

func parseSSH(out *option.SSHOutboundOptions, u *url.URL) error {
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
		portStr = "22"
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("invalid ssh port: %w", err)
	}
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
	out.User = u.User.Username()
	if pass, ok := u.User.Password(); ok {
		out.Password = pass
	}
	return nil
}

func parseShadowTLS(out *option.ShadowTLSOutboundOptions, u *url.URL) error {
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("shadowtls host/port invalid: %w", err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("invalid shadowtls port: %w", err)
	}
	params := u.Query()
	v, _ := strconv.Atoi(params.Get("version"))
	if v == 0 {
		v = 2
	}
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
	out.Password = u.User.Username()
	out.Version = v
	parseTLS(params, &out.OutboundTLSOptionsContainer, host)
	return nil
}

func parseAnyTLS(out *option.AnyTLSOutboundOptions, u *url.URL) error {
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("anytls host/port invalid: %w", err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("invalid anytls port: %w", err)
	}
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
	out.Password = u.User.Username()
	parseTLS(u.Query(), &out.OutboundTLSOptionsContainer, host)
	return nil
}

func parseTransport(params url.Values, host string) (*option.V2RayTransportOptions, error) {
	transportType := strings.ToLower(params.Get("type"))
	headerType := strings.ToLower(params.Get("headerType"))

	if (transportType == "tcp" || transportType == "") && headerType == "http" {
		transportType = "httpupgrade"
	}

	if idx := strings.IndexAny(transportType, "=@"); idx != -1 {
		transportType = transportType[:idx]
	}

	if transportType == "xhttp" {
		transportType = "httpupgrade"
	}

	if transportType == "" || transportType == "tcp" {
		return nil, nil
	}

	transport := &option.V2RayTransportOptions{Type: transportType}
	switch transport.Type {
	case "ws":
		wsHost := params.Get("host")
		if wsHost == "" {
			wsHost = host
		}
		transport.WebsocketOptions.Path = params.Get("path")
		if wsHost != "" {
			transport.WebsocketOptions.Headers = badoption.HTTPHeader{"Host": {wsHost}}
		}
	case "grpc":
		serviceName := params.Get("serviceName")
		if serviceName == "" {
			serviceName = params.Get("path")
		}
		transport.GRPCOptions.ServiceName = serviceName
	case "httpupgrade":
		obfuscationHost := params.Get("host")
		if obfuscationHost == "" {
			obfuscationHost = host
		}

		path := params.Get("path")
		if path == "" {
			path = "/"
		}

		transport.HTTPUpgradeOptions.Host = obfuscationHost
		transport.HTTPUpgradeOptions.Path = path
		if transport.HTTPUpgradeOptions.Host != "" {
			transport.HTTPUpgradeOptions.Headers = badoption.HTTPHeader{"Host": {transport.HTTPUpgradeOptions.Host}}
		}
	//case "kcp":
	//	transport.KCPOptions = &option.KCPInboundOptions{
	//		Seed: params.Get("seed"),
	//	}
	default:
		return nil, fmt.Errorf("invalid transport type '%s'", transport.Type)
	}
	return transport, nil
}

func parseTLS(params url.Values, tls *option.OutboundTLSOptionsContainer, fallbackSNI string) {
	security := strings.ToLower(params.Get("security"))
	if (security == "none" || security == "") && tls.TLS == nil {
		return
	}
	if tls.TLS == nil {
		tls.TLS = new(option.OutboundTLSOptions)
	}
	tls.TLS.Enabled = true
	sni := params.Get("sni")
	if sni == "" {
		sni = params.Get("host")
	}
	if sni == "" {
		sni = fallbackSNI
	}
	tls.TLS.ServerName = sni
	if security == "reality" {
		pbk := params.Get("pbk")
		if pbk == "" {
			tls.TLS = nil
			return
		}
		sid := params.Get("sid")
		if idx := strings.IndexAny(sid, "@"); idx != -1 {
			sid = sid[:idx]
		}
		tls.TLS.Insecure = false
		tls.TLS.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: pbk,
			ShortID:   sid,
		}
		if tls.TLS.UTLS == nil {
			tls.TLS.UTLS = new(option.OutboundUTLSOptions)
		}
		tls.TLS.UTLS.Enabled = true
		if fp := params.Get("fp"); fp != "" {
			tls.TLS.UTLS.Fingerprint = fp
		} else {
			tls.TLS.UTLS.Fingerprint = "chrome"
		}
	} else {
		tls.TLS.Insecure = parseBool(params.Get("allowInsecure")) || parseBool(params.Get("insecure"))
	}
	if alpn := params.Get("alpn"); alpn != "" {
		tls.TLS.ALPN = strings.Split(alpn, ",")
	}
	if fp := params.Get("fp"); fp != "" {
		if tls.TLS.UTLS == nil {
			tls.TLS.UTLS = new(option.OutboundUTLSOptions)
		}
		tls.TLS.UTLS.Enabled = true
		tls.TLS.UTLS.Fingerprint = fp
	}
}

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
