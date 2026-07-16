package singproxy

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

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
	encryption := params.Get("encryption")
	if encryption != "" {
		encryption = strings.SplitN(encryption, "=", 2)[0]
	}
	if encryption != "" && encryption != "none" && !strings.HasPrefix(encryption, "mlkem") {
		return fmt.Errorf("unsupported vless encryption: %s (sing-box only supports none)", encryption)
	}
	if transport, err := parseTransport(params, host); err == nil {
		out.Transport = transport
	} else {
		return err
	}
	parseTLS(params, &out.OutboundTLSOptionsContainer, host)
	parseMultiplex(params, &out.Multiplex)
	if pe := params.Get("packetEncoding"); pe == "xudp" {
		out.PacketEncoding = &pe
	}
	return nil
}
