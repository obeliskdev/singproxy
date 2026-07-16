package singproxy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/sagernet/sing-box/option"
)

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
