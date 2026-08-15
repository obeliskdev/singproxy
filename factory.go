package singproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/route"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type SingBoxProxy struct {
	options   any
	outbound  adapter.Outbound
	original  string
	proxyIP   net.IP
	typed     string
	cfg       Config
	startMu   sync.Mutex
	started   bool
	startFunc func() error
}

var globalBox *singBoxContext

type singBoxContext struct {
	ctx              context.Context
	outboundRegistry adapter.OutboundRegistry
	endpointRegistry adapter.EndpointRegistry
	logger           log.ContextLogger
}

func init() {
	ctx := box.Context(
		context.Background(),
		include.InboundRegistry(),
		include.OutboundRegistry(),
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
		include.ServiceRegistry(),
	)

	nopLogger := logger.NOP()

	endpointRegistry := service.FromContext[adapter.EndpointRegistry](ctx)
	outboundRegistry := service.FromContext[adapter.OutboundRegistry](ctx)
	inboundRegistry := service.FromContext[adapter.InboundRegistry](ctx)
	dnsTransportRegistry := service.FromContext[adapter.DNSTransportRegistry](ctx)

	if endpointRegistry == nil {
		panic("missing endpoint registry in context")
	}
	if outboundRegistry == nil {
		panic("missing outbound registry in context")
	}
	if dnsTransportRegistry == nil {
		panic("missing dnsTransportRegistry in context")
	}

	endpointManager := endpoint.NewManager(nopLogger, endpointRegistry)
	outboundManager := outbound.NewManager(nopLogger, outboundRegistry, endpointManager, "")
	dnsTransportManager := dns.NewTransportManager(nopLogger, dnsTransportRegistry, outboundManager, "")
	connManager := route.NewConnectionManager(nopLogger)
	inboundManager := inbound.NewManager(nopLogger, inboundRegistry, endpointManager)

	dnsTransportManager.Initialize(func() (adapter.DNSTransport, error) {
		return local.NewTransport(ctx, nopLogger, "local", option.LocalDNSServerOptions{})
	})

	service.MustRegister[adapter.EndpointManager](ctx, endpointManager)
	service.MustRegister[adapter.OutboundManager](ctx, outboundManager)
	service.MustRegister[adapter.DNSTransportManager](ctx, dnsTransportManager)
	service.MustRegister[adapter.ConnectionManager](ctx, connManager)
	service.MustRegister[adapter.InboundManager](ctx, inboundManager)

	if err := dnsTransportManager.Start(adapter.StartStateStart); err != nil {
		panic(fmt.Sprintf("failed to start DNS transport manager: %v", err))
	}

	dnsRouter := dns.NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{})
	service.MustRegister[adapter.DNSRouter](ctx, dnsRouter)
	if err := dnsRouter.Start(adapter.StartStateStart); err != nil {
		panic(fmt.Sprintf("failed to start DNS router: %v", err))
	}

	globalBox = &singBoxContext{
		ctx:              ctx,
		outboundRegistry: outboundRegistry,
		endpointRegistry: endpointRegistry,
		logger:           nopLogger,
	}
}

func FromURL(cfg Config, proxyURL string) (Proxy, error) {
	cfg = cfg.withDefaults()

	if proxyURL == "" {
		return nil, fmt.Errorf("%w: proxy string is empty", ErrInvalidProxyFormat)
	}
	if proxyURL == "direct" {
		if cfg.DirectTimeout == defaultDirectTimeout {
			return Direct, nil
		}
		return newDirectProxy(cfg), nil
	}

	cleanedURL := cleanProxyURL(proxyURL)

	if !strings.Contains(cleanedURL, "://") {
		if !strings.Contains(cleanedURL, ":") {
			return nil, fmt.Errorf("%w: schemeless proxy needs host:port", ErrInvalidProxyFormat)
		}
		cleanedURL = "http://" + cleanedURL
	}

	u, err := url.Parse(cleanedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy: %w", err)
	}

	proxyType, err := getProxyType(u.Scheme)
	if err != nil {
		return nil, err
	}

	if isXHTTPTransport(u) {
		return newXHTTPProxy(proxyURL, u, proxyType, cfg)
	}

	return newSingBoxProxy(proxyURL, u, proxyType, cfg)
}

func newSingBoxProxy(
	originalURL string,
	parsedURL *url.URL,
	typed string,
	cfg Config,
) (*SingBoxProxy, error) {
	p := &SingBoxProxy{
		original: originalURL,
		typed:    typed,
		cfg:      cfg,
	}

	if typed == "wireguard" {
		return newWireGuardProxy(p, parsedURL)
	}

	options, loaded := globalBox.outboundRegistry.CreateOptions(p.typed)
	if !loaded {
		return nil, fmt.Errorf("unknown proxy type: %s", p.typed)
	}

	if err := parseProxyURL(options, parsedURL, typed, cfg.DialTimeout); err != nil {
		return nil, fmt.Errorf("parsing %s failed: %w", originalURL, err)
	}

	createOutbound, err := globalBox.outboundRegistry.CreateOutbound(globalBox.ctx, nil, globalBox.logger, "", p.typed, options)
	if err != nil {
		return nil, fmt.Errorf("create %s outbound failed: %w", p.typed, err)
	}

	p.options = options
	p.outbound = createOutbound
	p.resolveHostAddr()
	return p, nil
}

func FromURLs(cfg Config, urls ...string) ([]Proxy, []error) {
	var (
		proxies = make([]Proxy, 0, len(urls))
		errs    = make([]error, 0)
		wg      sync.WaitGroup
	)

	results := make(chan struct {
		proxy Proxy
		err   error
	}, len(urls))

	for i, u := range urls {
		wg.Add(1)
		go func(index int, urlStr string) {
			defer wg.Done()
			proxy, err := FromURL(cfg, urlStr)
			if err != nil {
				err = fmt.Errorf("url #%d (%s): %w", index, urlStr, err)
			}
			results <- struct {
				proxy Proxy
				err   error
			}{proxy, err}
		}(i, u)
	}

	wg.Wait()
	close(results)

	for res := range results {
		if res.err != nil {
			errs = append(errs, res.err)
		} else if res.proxy != nil {
			proxies = append(proxies, res.proxy)
		}
	}

	return proxies, errs
}

func (p *SingBoxProxy) String() string {
	return p.original
}

func (p *SingBoxProxy) Addr() net.IP {
	return p.proxyIP
}

func (p *SingBoxProxy) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	if addr == "" {
		return nil, ErrMissingTarget
	}
	return p.dialSocksaddr(ctx, network, metadata.ParseSocksaddr(addr))
}

func (p *SingBoxProxy) DialContextAddr(ctx context.Context, network string, addr *net.TCPAddr) (net.Conn, error) {
	if addr == nil {
		return nil, ErrMissingTarget
	}
	return p.dialSocksaddr(ctx, network, metadata.SocksaddrFromNet(addr))
}

func (p *SingBoxProxy) dialSocksaddr(ctx context.Context, network string, targetAddr metadata.Socksaddr) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
	}

	if err := p.ensureStarted(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()

	conn, err := p.outbound.DialContext(ctx, network, targetAddr)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ErrProxyDialTimeoutReached
		}
		return nil, err
	}
	return conn, nil
}

func (p *SingBoxProxy) ensureStarted() error {
	if p.startFunc == nil {
		return nil
	}
	p.startMu.Lock()
	defer p.startMu.Unlock()
	if p.started {
		return nil
	}
	if err := p.startFunc(); err != nil {
		return err
	}
	p.started = true
	return nil
}

func (p *SingBoxProxy) resolveHostAddr() {
	host, ok := p.options.(option.ServerOptionsWrapper)
	if !ok {
		return
	}
	p.proxyIP = resolveHostIP(host.TakeServerOptions().Server)
}

func resolveHostIP(host string) net.IP {
	if host == "" {
		return nil
	}
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		return parsedIP
	}
	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		return ips[0]
	}
	return nil
}
