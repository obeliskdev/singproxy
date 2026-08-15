package singproxy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

type vmessLinkData struct {
	V               any    `json:"v"`
	PS              string `json:"ps"`
	Add             string `json:"add"`
	Port            any    `json:"port"`
	ID              string `json:"id"`
	Aid             any    `json:"aid"`
	Net             any    `json:"net"`
	Host            any    `json:"host"`
	Path            any    `json:"path"`
	TLS             any    `json:"tls"`
	SNI             any    `json:"sni"`
	ALPN            any    `json:"alpn"`
	FP              any    `json:"fp"`
	AllowInsecure   any    `json:"allowInsecure"`
	Security        string `json:"security"`
	PacketEncoding  string `json:"packet_encoding"`
	GlobalPadding   bool   `json:"global_padding"`
	AuthLength      bool   `json:"authenticated_length"`
	ServiceNameGRPC string `json:"serviceName"`
}

func parseVMess(out *option.VMessOutboundOptions, u *url.URL) error {
	payload, err := extractVMessPayload(u)
	if err != nil {
		return err
	}
	return parseVMessBase64(out, payload)
}

func parseVMessBase64(out *option.VMessOutboundOptions, b64 string) error {
	jsonBytes, err := base64Decode(b64)
	if err != nil {
		return fmt.Errorf("failed to decode vmess data: %w", err)
	}
	var data vmessLinkData
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return fmt.Errorf("failed to unmarshal vmess JSON: %w", err)
	}
	port, err := parsePort(data.Port)
	if err != nil {
		return fmt.Errorf("invalid vmess port: %w", err)
	}
	alterID, _ := parseAlterID(data.Aid)
	out.ServerOptions = option.ServerOptions{Server: data.Add, ServerPort: port}
	out.UUID = data.ID
	out.Security = "auto"
	if data.Security != "" {
		out.Security = data.Security
	}
	out.AlterId = alterID
	out.GlobalPadding = data.GlobalPadding
	out.AuthenticatedLength = data.AuthLength
	out.Network = option.NetworkList(strings.Join([]string{N.NetworkTCP, N.NetworkUDP}, "\n"))
	out.PacketEncoding = data.PacketEncoding
	if networkType := strings.ToLower(anyToString(data.Net)); networkType != "tcp" && networkType != "" && networkType != "raw" {
		host := anyToString(data.Host)
		path := anyToString(data.Path)
		transport := &option.V2RayTransportOptions{Type: networkType}
		switch transport.Type {
		case "ws", "websocket":
			transport.Type = "ws"
			transport.WebsocketOptions.Path = path
			if host != "" {
				transport.WebsocketOptions.Headers = badoption.HTTPHeader{"Host": {host}}
			}
		case "grpc":
			transport.GRPCOptions.ServiceName = data.ServiceNameGRPC
			if transport.GRPCOptions.ServiceName == "" {
				transport.GRPCOptions.ServiceName = path
			}
		case "httpupgrade":
			transport.HTTPUpgradeOptions.Host = host
			transport.HTTPUpgradeOptions.Path = path
			if host != "" {
				transport.HTTPUpgradeOptions.Headers = badoption.HTTPHeader{"Host": {host}}
			}
		case "http":
			transport.HTTPOptions.Path = path
			if host != "" {
				transport.HTTPOptions.Host = badoption.Listable[string]{host}
				transport.HTTPOptions.Headers = badoption.HTTPHeader{"Host": {host}}
			}
		default:
			return fmt.Errorf("unsupported vmess network: %s", transport.Type)
		}
		out.Transport = transport
	}
	tlsType := strings.ToLower(anyToString(data.TLS))
	if tlsType == "" && strings.ToLower(data.Security) == "tls" {
		tlsType = "tls"
	}
	if tlsType == "tls" {
		sni := anyToString(data.SNI)
		out.TLS = new(option.OutboundTLSOptions)
		params := url.Values{}
		params.Set("sni", sni)
		if host := anyToString(data.Host); host != "" && sni == "" {
			params.Set("sni", host)
		}
		params.Set("allowInsecure", anyToString(data.AllowInsecure))
		params.Set("alpn", anyToString(data.ALPN))
		params.Set("fp", anyToString(data.FP))
		params.Set("security", "tls")
		parseTLS(params, &out.OutboundTLSOptionsContainer, data.Add)
	}
	return nil
}
