package singproxy

import (
	"context"
	stdtls "crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"

	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

type xhttpTLSConfig struct {
	singBoxConfig boxTLS.Config
	isReality     bool
	serverName    string
	alpn          []string
	insecure      bool
}

func newXHTTPTLSConfig(ctx context.Context, params tlsParams) (*xhttpTLSConfig, error) {
	tlsOpts := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: params.sni,
		Insecure:   params.insecure,
		ALPN:       params.alpn,
	}

	if params.reality {
		tlsOpts.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: params.publicKey,
			ShortID:   params.shortID,
		}
		tlsOpts.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: params.fingerprint,
		}
		if tlsOpts.UTLS.Fingerprint == "" {
			tlsOpts.UTLS.Fingerprint = "chrome"
		}
	} else if params.fingerprint != "" {
		tlsOpts.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: params.fingerprint,
		}
	}

	var cfg boxTLS.Config
	var err error
	if params.reality {
		cfg, err = boxTLS.NewRealityClient(ctx, params.serverAddress, *tlsOpts)
	} else {
		cfg, err = boxTLS.NewClient(ctx, params.serverAddress, *tlsOpts)
	}
	if err != nil {
		return nil, fmt.Errorf("xhttp tls config: %w", err)
	}

	return &xhttpTLSConfig{
		singBoxConfig: cfg,
		isReality:     params.reality,
		serverName:    params.sni,
		alpn:          params.alpn,
		insecure:      params.insecure,
	}, nil
}

func (c *xhttpTLSConfig) WrapConn(ctx context.Context, raw net.Conn, isH2 bool) (net.Conn, error) {
	if c == nil {
		return raw, nil
	}
	if c.singBoxConfig != nil {
		return boxTLS.ClientHandshake(ctx, raw, c.singBoxConfig)
	}
	tlsCfg := &stdtls.Config{
		ServerName:         c.serverName,
		InsecureSkipVerify: c.insecure,
		NextProtos:         c.alpn,
	}
	if len(tlsCfg.NextProtos) == 0 {
		if isH2 {
			tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		} else {
			tlsCfg.NextProtos = []string{"http/1.1"}
		}
	}
	tlsConn := stdtls.Client(raw, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("xhttp tls handshake: %w", err)
	}
	return tlsConn, nil
}

type tlsParams struct {
	serverAddress string
	sni           string
	insecure      bool
	alpn          []string
	fingerprint   string
	reality       bool
	publicKey     string
	shortID       string
	enabled       bool
}

func parseTLSParams(query url.Values, serverAddress string) tlsParams {
	sni := query.Get("sni")
	if sni == "" {
		sni = query.Get("host")
	}
	if sni == "" {
		sni = serverAddress
		if h, _, err := net.SplitHostPort(sni); err == nil {
			sni = h
		}
	}
	p := tlsParams{
		serverAddress: serverAddress,
		sni:           sni,
		insecure:      parseBool(query.Get("allowInsecure")) || parseBool(query.Get("insecure")) || parseBool(query.Get("allow_insecure")),
		fingerprint:   query.Get("fp"),
	}
	if alpn := query.Get("alpn"); alpn != "" {
		p.alpn = strings.Split(alpn, ",")
	}
	security := strings.ToLower(query.Get("security"))
	if security == "reality" {
		pk := query.Get("pbk")
		if pk != "" {
			p.reality = true
			p.publicKey = pk
			p.shortID = query.Get("sid")
			if idx := strings.IndexAny(p.shortID, "@"); idx != -1 {
				p.shortID = p.shortID[:idx]
			}
		}
	}
	// TLS is enabled if any of these explicit indicators are present
	if security == "tls" || security == "reality" || p.insecure || p.fingerprint != "" || len(p.alpn) > 0 ||
		query.Get("sni") != "" || query.Get("allowInsecure") != "" || query.Get("allow_insecure") != "" {
		p.enabled = true
	}
	return p
}
