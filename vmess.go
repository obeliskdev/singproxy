package singproxy

import (
	"encoding/json"
	"errors"
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
	Type            any    `json:"type"`
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

func (d *vmessLinkData) StringField(field any) string {
	if field == nil {
		return ""
	}
	switch v := field.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return fmt.Sprintf("%v", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (d *vmessLinkData) NetStr() string           { return d.StringField(d.Net) }
func (d *vmessLinkData) TypeStr() string          { return d.StringField(d.Type) }
func (d *vmessLinkData) HostStr() string          { return d.StringField(d.Host) }
func (d *vmessLinkData) PathStr() string          { return d.StringField(d.Path) }
func (d *vmessLinkData) TLSStr() string           { return d.StringField(d.TLS) }
func (d *vmessLinkData) SNIStr() string           { return d.StringField(d.SNI) }
func (d *vmessLinkData) ALPNStr() string          { return d.StringField(d.ALPN) }
func (d *vmessLinkData) FPStr() string            { return d.StringField(d.FP) }
func (d *vmessLinkData) AllowInsecureStr() string { return d.StringField(d.AllowInsecure) }

func parseVMess(out *option.VMessOutboundOptions, u *url.URL) error {
	var payload string
	if u.Opaque != "" {
		payload = u.Opaque
	} else if u.Host != "" {
		payload = u.Host
		if u.Path != "" {
			payload = payload + u.Path
		}
		if u.ForceQuery || u.RawQuery != "" {
			payload = payload + "?" + u.RawQuery
		}
	} else {
		return errors.New("unrecognized vmess URL format")
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
	if networkType := strings.ToLower(data.NetStr()); networkType != "tcp" && networkType != "" && networkType != "raw" {
		transport := &option.V2RayTransportOptions{Type: networkType}
		switch transport.Type {
		case "ws", "websocket":
			transport.Type = "ws"
			transport.WebsocketOptions.Path = data.PathStr()
			if host := data.HostStr(); host != "" {
				transport.WebsocketOptions.Headers = badoption.HTTPHeader{"Host": {host}}
			}
		case "grpc":
			transport.GRPCOptions.ServiceName = data.ServiceNameGRPC
			if transport.GRPCOptions.ServiceName == "" {
				transport.GRPCOptions.ServiceName = data.PathStr()
			}
		case "httpupgrade":
			transport.HTTPUpgradeOptions.Host = data.HostStr()
			transport.HTTPUpgradeOptions.Path = data.PathStr()
			if host := data.HostStr(); host != "" {
				transport.HTTPUpgradeOptions.Headers = badoption.HTTPHeader{"Host": {host}}
			}
		case "http":
			transport.HTTPOptions.Path = data.PathStr()
			if host := data.HostStr(); host != "" {
				transport.HTTPOptions.Host = badoption.Listable[string]{host}
				transport.HTTPOptions.Headers = badoption.HTTPHeader{"Host": {host}}
			}
		default:
			return fmt.Errorf("unsupported vmess network: %s", transport.Type)
		}
		out.Transport = transport
	}
	tlsType := strings.ToLower(data.TLSStr())
	if tlsType == "" && strings.ToLower(data.Security) == "tls" {
		tlsType = "tls"
	}
	if tlsType == "tls" {
		out.TLS = new(option.OutboundTLSOptions)
		params := url.Values{}
		params.Set("sni", data.SNIStr())
		if host := data.HostStr(); host != "" && data.SNIStr() == "" {
			params.Set("sni", host)
		}
		params.Set("allowInsecure", data.AllowInsecureStr())
		params.Set("alpn", data.ALPNStr())
		params.Set("fp", data.FPStr())
		params.Set("security", "tls")
		parseTLS(params, &out.OutboundTLSOptionsContainer, data.Add)
	}
	return nil
}
