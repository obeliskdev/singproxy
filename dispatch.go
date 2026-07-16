package singproxy

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

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
	case "ssr", "shadowsocksr":
		return "shadowsocksr", nil
	case "tuic":
		return "tuic", nil
	case "hy", "hysteria":
		return "hysteria", nil
	case "hy2", "hysteria2":
		return "hysteria2", nil
	case "ssh":
		return "ssh", nil
	case "socks", "socks5", "socks4", "socks4a":
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
	case "shadowsocksr":
		options := out.(*option.ShadowsocksROutboundOptions)
		options.DialerOptions = dialerOptions
		return parseShadowsocksR(options, u)
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
