package singproxy

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

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
	normalizeTrojanGoParams(params)
	if transport, err := parseTransport(params, host); err == nil {
		out.Transport = transport
	} else {
		return err
	}
	parseTLS(params, &out.OutboundTLSOptionsContainer, host)
	return nil
}
