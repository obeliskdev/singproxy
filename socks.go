package singproxy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/option"
)

func parseSOCKS(out *option.SOCKSOutboundOptions, u *url.URL) error {
	if u.User == nil && u.Host != "" {
		if decoded, err := base64Decode(u.Host); err == nil && strings.Contains(string(decoded), "@") {
			decodedURL, err := url.Parse("socks://" + string(decoded))
			if err != nil {
				return fmt.Errorf("failed to parse decoded socks url: %w", err)
			}
			u = decodedURL
		}
	}
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
