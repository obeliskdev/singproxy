package singproxy

import (
	"context"
	"net"
	"time"
)

type Proxy interface {
	String() string
	Addr() net.IP
	DialContextAddr(ctx context.Context, network string, addr *net.TCPAddr) (net.Conn, error)
	DialContext(ctx context.Context, network string, addr string) (net.Conn, error)
}

type directProxy struct {
	timeout time.Duration
}

func newDirectProxy(cfg Config) *directProxy {
	return &directProxy{timeout: cfg.withDefaults().DirectTimeout}
}

func (d directProxy) String() string {
	return "direct"
}

func (d directProxy) Addr() net.IP {
	return net.IPv4zero
}

func (d directProxy) dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   d.timeout,
		KeepAlive: d.timeout,
	}
}

func (d directProxy) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	return d.dialer().DialContext(ctx, network, addr)
}

func (d directProxy) DialContextAddr(ctx context.Context, network string, addr *net.TCPAddr) (net.Conn, error) {
	return d.dialer().DialContext(ctx, network, addr.String())
}

var Direct Proxy = newDirectProxy(DefaultConfig())
