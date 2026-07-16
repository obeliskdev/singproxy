package singproxy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/option"
)

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

	if strings.EqualFold(u.Scheme, "https") || strings.EqualFold(u.Scheme, "http2") {
		if out.TLS == nil {
			out.TLS = &option.OutboundTLSOptions{Enabled: true, ServerName: host}
		}
		if strings.EqualFold(u.Scheme, "http2") {
			out.TLS.ALPN = append(out.TLS.ALPN, "h2")
		}
	}

	return nil
}
