package singproxy

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

const wireGuardTag = "singproxy-wg"

func newWireGuardProxy(p *SingBoxProxy, u *url.URL) (*SingBoxProxy, error) {
	options := &option.WireGuardEndpointOptions{
		DialerOptions: option.DialerOptions{
			ReuseAddr:      true,
			ConnectTimeout: badoption.Duration(p.cfg.DialTimeout),
		},
	}
	if err := parseWireGuard(options, u); err != nil {
		return nil, fmt.Errorf("parsing %s failed: %w", p.original, err)
	}

	if globalBox.endpointRegistry == nil {
		return nil, fmt.Errorf("missing endpoint registry in context")
	}
	wgEndpoint, err := globalBox.endpointRegistry.Create(globalBox.ctx, nil, globalBox.logger, wireGuardTag, "wireguard", options)
	if err != nil {
		return nil, fmt.Errorf("create wireguard endpoint failed: %w", err)
	}

	p.options = options
	p.outbound = wgEndpoint
	p.startFunc = func() error {
		if err := wgEndpoint.Start(adapter.StartStateStart); err != nil {
			return fmt.Errorf("start wireguard endpoint failed: %w", err)
		}
		if err := wgEndpoint.Start(adapter.StartStatePostStart); err != nil {
			return fmt.Errorf("start wireguard endpoint failed: %w", err)
		}
		return nil
	}
	p.proxyIP = wireGuardLocalIP(options.Address)
	return p, nil
}

// wireGuardLocalIP extracts the first local tunnel address from the
// configured address prefixes. The proxy address of a WireGuard tunnel
// is the address the client itself holds inside the tunnel, not the
// public peer endpoint.
func wireGuardLocalIP(prefixes []netip.Prefix) net.IP {
	if len(prefixes) == 0 {
		return nil
	}
	addr := prefixes[0].Addr()
	if addr.Is4() {
		return net.IP(addr.AsSlice())
	}
	return addr.AsSlice()
}

func parseWireGuard(out *option.WireGuardEndpointOptions, u *url.URL) error {
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
	unescapedKey, _ := url.PathUnescape(u.User.Username())
	peerPublicKey, _ := url.PathUnescape(params.Get("publickey"))

	allowedIPs, err := parseNetIPPrefixList(params.Get("allowedips"))
	if err != nil {
		return fmt.Errorf("invalid wireguard allowedips: %w", err)
	}
	if len(allowedIPs) == 0 {
		allowedIPs = []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}
	}

	out.Address = localAddr
	out.PrivateKey = unescapedKey
	out.MTU = uint32(mtu)
	out.Peers = []option.WireGuardPeer{
		{
			Address:      host,
			Port:         port,
			PublicKey:    peerPublicKey,
			PreSharedKey: params.Get("presharedkey"),
			AllowedIPs:   allowedIPs,
		},
	}
	return nil
}
