package singproxy

import (
	"context"
	"fmt"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/route"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type SingBoxProxy struct {
	options  any
	outbound adapter.Outbound
	original string
	proxyIP  net.IP
	typed    string
	cfg      Config
}

var globalBox *singBoxContext

type singBoxContext struct {
	ctx              context.Context
	outboundRegistry adapter.OutboundRegistry
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

	dnsRouter := dns.NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{})

	service.MustRegister[adapter.DNSRouter](ctx, dnsRouter)
	service.MustRegister[adapter.EndpointManager](ctx, endpointManager)
	service.MustRegister[adapter.OutboundManager](ctx, outboundManager)
	service.MustRegister[adapter.DNSTransportManager](ctx, dnsTransportManager)
	service.MustRegister[adapter.ConnectionManager](ctx, connManager)
	service.MustRegister[adapter.InboundManager](ctx, inboundManager)

	localTransport, err := local.NewTransport(
		ctx,
		nopLogger,
		"local",
		option.LocalDNSServerOptions{},
	)

	if err != nil {
		panic(fmt.Sprintf("failed to create local DNS transport: %v", err))
	}
	dnsTransportManager.Initialize(localTransport)

	globalBox = &singBoxContext{
		ctx:              ctx,
		outboundRegistry: outboundRegistry,
		logger:           nopLogger,
	}
}

func FromURL(cfg Config, proxyURL string) (Proxy, error) {
	cfg = cfg.withDefaults()

	if proxyURL == "" {
		return nil, fmt.Errorf("%w: proxy string is empty", ErrInvalidProxyFormat)
	}
	if proxyURL == "direct" {
		if cfg.DirectTimeout == 0 || cfg.DirectTimeout == defaultDirectTimeout {
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
	p.resolveAndStoreAddr()
	return p, nil
}

func FromURLs(cfg Config, urls ...string) ([]Proxy, []error) {
	var (
		proxies = make([]Proxy, 0, len(urls))
		errors  = make([]error, 0)
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
			errors = append(errors, res.err)
		} else if res.proxy != nil {
			proxies = append(proxies, res.proxy)
		}
	}

	return proxies, errors
}

func (p *SingBoxProxy) String() string {
	return p.original
}

func (p *SingBoxProxy) Addr() net.IP {
	return p.proxyIP
}

type connResult struct {
	conn net.Conn
	err  error
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

	resC := make(chan connResult, 1)
	go func() {
		conn, err := p.outbound.DialContext(context.Background(), network, targetAddr)
		resC <- connResult{conn, err}
	}()

	timer := time.NewTimer(p.cfg.DialTimeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		go discardResult(resC)
		return nil, ctx.Err()
	case <-timer.C:
		go discardResult(resC)
		return nil, ErrProxyDialTimeoutReached
	case res := <-resC:
		return res.conn, res.err
	}
}

func discardResult(resC <-chan connResult) {
	if res := <-resC; res.conn != nil {
		_ = res.conn.Close()
	}
}

func (p *SingBoxProxy) resolveAndStoreAddr() {
	v := reflect.ValueOf(p.options)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}

	host := v.FieldByName("Server").String()
	if host == "" {
		if so := v.FieldByName("ServerOptions"); so.IsValid() {
			if so.Kind() == reflect.Ptr {
				so = so.Elem()
			}
			if so.Kind() == reflect.Struct {
				host = so.FieldByName("Server").String()
			}
		}
	}

	if host == "" {
		return
	}
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		p.proxyIP = parsedIP
		return
	}
	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		p.proxyIP = ips[0]
	}
}
