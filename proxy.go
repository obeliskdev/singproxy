package singproxy

import (
	"context"
	"net"
	"time"
)

var proxyOptions = &net.Dialer{
	Timeout: 5 * time.Second,
}

type Proxy interface {
	String() string
	Addr() net.IP
	DialContext(ctx context.Context, network string, addr *net.TCPAddr) (net.Conn, error)
}

type directProxy struct{}

func (d directProxy) String() string {
	return "direct"
}

func (d directProxy) Addr() net.IP {
	return net.IPv4zero
}

func (d directProxy) DialContext(ctx context.Context, network string, addr *net.TCPAddr) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   proxyOptions.Timeout,
		KeepAlive: proxyOptions.Timeout,
	}
	return dialer.DialContext(ctx, network, addr.String())
}

var Direct Proxy = &directProxy{}
