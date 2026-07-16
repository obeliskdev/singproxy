package singproxy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

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
