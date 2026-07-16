package singproxy

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func parseTransport(params url.Values, host string) (*option.V2RayTransportOptions, error) {
	transportType := strings.ToLower(params.Get("type"))
	headerType := strings.ToLower(params.Get("headerType"))

	if (transportType == "tcp" || transportType == "") && headerType == "http" {
		transportType = "httpupgrade"
	}

	if idx := strings.IndexAny(transportType, "=@"); idx != -1 {
		transportType = transportType[:idx]
	}

	if transportType == "xhttp" || transportType == "splithttp" {
		return nil, nil
	}

	if transportType == "" || transportType == "tcp" || transportType == "raw" {
		return nil, nil
	}

	transport := &option.V2RayTransportOptions{Type: transportType}
	switch transport.Type {
	case "ws", "websocket":
		transport.Type = "ws"
		wsHost := params.Get("host")
		if wsHost == "" {
			wsHost = host
		}
		transport.WebsocketOptions.Path = params.Get("path")
		if wsHost != "" {
			transport.WebsocketOptions.Headers = badoption.HTTPHeader{"Host": {wsHost}}
		}
	case "grpc":
		serviceName := params.Get("serviceName")
		if serviceName == "" {
			serviceName = params.Get("path")
		}
		transport.GRPCOptions.ServiceName = serviceName
	case "http":
		httpHost := params.Get("host")
		if httpHost == "" {
			httpHost = host
		}
		transport.HTTPOptions.Path = params.Get("path")
		if httpHost != "" {
			transport.HTTPOptions.Host = badoption.Listable[string]{httpHost}
			transport.HTTPOptions.Headers = badoption.HTTPHeader{"Host": {httpHost}}
		}
	case "httpupgrade":
		obfuscationHost := params.Get("host")
		if obfuscationHost == "" {
			obfuscationHost = host
		}

		path := params.Get("path")
		if path == "" {
			path = "/"
		}

		transport.HTTPUpgradeOptions.Host = obfuscationHost
		transport.HTTPUpgradeOptions.Path = path
		if transport.HTTPUpgradeOptions.Host != "" {
			transport.HTTPUpgradeOptions.Headers = badoption.HTTPHeader{"Host": {transport.HTTPUpgradeOptions.Host}}
		}
	default:
		return nil, fmt.Errorf("invalid transport type '%s'", transport.Type)
	}
	return transport, nil
}
