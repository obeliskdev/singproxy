package singproxy

import (
	"context"
	"net"
	"time"
)

// Proxy is a parsed proxy. It can dial connections to arbitrary targets
// through the remote proxy server, and must be closed when no longer
// needed to release the underlying transport resources.
type Proxy interface {
	String() string
	Addr() net.IP
	DialContext(ctx context.Context, network string, addr string) (net.Conn, error)
	DialContextAddr(ctx context.Context, network string, addr *net.TCPAddr) (net.Conn, error)

	// Close releases all resources held by the proxy. It is safe to call
	// multiple times. Proxies that never allocate transport resources
	// (for example direct connections) may implement a no-op Close.
	Close() error
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

func (directProxy) Close() error {
	return nil
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
