package singproxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// parseNaive parses naive proxy URLs as used by the naive project
// (https://github.com/klzgrad/naiveproxy), for example:
//
//	naive+https://user:pass@example.com:443
//	naive://user:pass@example.com:443
//
// The https scheme variant implies TLS; the plain naive:// scheme is
// treated as HTTPS by default but can be downgraded with security=none.
func parseNaive(out *option.NaiveOutboundOptions, u *url.URL) error {
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("naive host/port invalid: %w", err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("invalid naive port: %w", err)
	}

	params := u.Query()
	out.ServerOptions = option.ServerOptions{Server: host, ServerPort: port}
	if u.User != nil {
		username, password := parseAuth(u.User.String())
		out.Username = username
		out.Password = password
	}
	if strings.HasSuffix(strings.ToLower(u.Scheme), "https") {
		out.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: host,
			Insecure:   parseBool(params.Get("insecure")) || parseBool(params.Get("allowInsecure")),
		}
		if sni := params.Get("sni"); sni != "" {
			out.TLS.ServerName = sni
		}
		if alpn := params.Get("alpn"); alpn != "" {
			out.TLS.ALPN = strings.Split(alpn, ",")
		}
		if fp := params.Get("fp"); fp != "" {
			out.TLS.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fp}
		}
	}
	if strings.EqualFold(params.Get("security"), "none") {
		out.TLS = nil
	}
	if out.Username == "" && out.Password == "" {
		return errors.New("naive proxy missing credentials")
	}
	return nil
}
