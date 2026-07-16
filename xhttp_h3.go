package singproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

func newXhttpH3Transport(tlsCfg *xhttpTLSConfig, keepAlivePeriod time.Duration, dialRaw func(ctx context.Context) (net.Conn, error)) (http.RoundTripper, error) {
	if keepAlivePeriod == 0 {
		keepAlivePeriod = xhttpQuicgoH3KeepAlivePeriod
	}
	if keepAlivePeriod < 0 {
		keepAlivePeriod = 0
	}

	var stdTLSConfig *tls.Config
	if tlsCfg != nil {
		if cfg, err := tlsCfg.singBoxConfig.Config(); err == nil && cfg != nil {
			stdTLSConfig = cfg.Clone()
		}
		if stdTLSConfig == nil {
			stdTLSConfig = &tls.Config{
				ServerName:         tlsCfg.serverName,
				InsecureSkipVerify: tlsCfg.insecure,
			}
		}
		if len(stdTLSConfig.NextProtos) == 0 {
			stdTLSConfig.NextProtos = []string{"h3"}
		}
	} else {
		stdTLSConfig = &tls.Config{NextProtos: []string{"h3"}}
	}

	quicConfig := &quic.Config{
		MaxIncomingStreams: -1,
		KeepAlivePeriod:    keepAlivePeriod,
		MaxIdleTimeout:     xhttpConnIdleTimeout,
	}

	transport := &http3.Transport{
		TLSClientConfig: stdTLSConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, addr string, tlsCfg2 *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := net.LookupPort("udp", portStr)
			if err != nil {
				return nil, err
			}
			udpAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
			if udpAddr.IP == nil {
				ips, err := net.LookupIP(host)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("xhttp h3: resolve %s: %w", host, err)
				}
				udpAddr.IP = ips[0]
			}
			udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				return nil, fmt.Errorf("xhttp h3: listen udp: %w", err)
			}
			return quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg2, cfg)
		},
	}

	return transport, nil
}
