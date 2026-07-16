package singproxy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
)

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
