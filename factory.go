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
	"regexp"
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
	timeout  time.Duration
}

var globalBox *singBoxContext
var nonBase64Chars = regexp.MustCompile("[^a-zA-Z0-9+/=_-]")

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

func FromURL(timeout time.Duration, proxyURL string) (Proxy, error) {
	if proxyURL == "" {
		return nil, fmt.Errorf("%w: proxy string is empty", ErrInvalidProxyFormat)
	}
	if proxyURL == "direct" {
		return Direct, nil
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

	return newSingBoxProxy(proxyURL, u, proxyType, timeout)
}

func newSingBoxProxy(
	originalURL string,
	parsedURL *url.URL,
	typed string,
	timeout time.Duration,
) (*SingBoxProxy, error) {
	p := &SingBoxProxy{
		original: originalURL,
		typed:    typed,
	}

	options, loaded := globalBox.outboundRegistry.CreateOptions(p.typed)
	if !loaded {
		return nil, fmt.Errorf("unknown proxy type: %s", p.typed)
	}

	if err := parseProxyURL(options, parsedURL, typed, timeout); err != nil {
		return nil, fmt.Errorf("parsing %s failed: %w", originalURL, err)
	}

	createOutbound, err := globalBox.outboundRegistry.CreateOutbound(globalBox.ctx, nil, globalBox.logger, "", p.typed, options)
	if err != nil {
		return nil, fmt.Errorf("create %s outbound failed: %w", p.typed, err)
	}

	p.options = options
	p.timeout = timeout
	p.outbound = createOutbound
	p.resolveAndStoreAddr()
	return p, nil
}

func FromURLs(timeout time.Duration, urls ...string) ([]Proxy, []error) {
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
			proxy, err := FromURL(timeout, urlStr)
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

func (p *SingBoxProxy) DialContext(ctx context.Context, network string, addr *net.TCPAddr) (net.Conn, error) {
	if addr == nil {
		return nil, ErrMissingTarget
	}

	if network != "tcp" && network != "udp" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
	}

	targetAddr := metadata.SocksaddrFromNet(addr)
	resC := make(chan connResult, 1)

	go func() {
		conn, err := p.outbound.DialContext(context.Background(), network, targetAddr)

		select {
		case resC <- connResult{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()

	timer := time.NewTimer(p.timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()

	case <-timer.C:
		return nil, ErrProxyDialTimeoutReached

	case res := <-resC:
		return res.conn, res.err
	}
}

func (p *SingBoxProxy) resolveAndStoreAddr() {
	var host string
	v := reflect.ValueOf(p.options)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return
	}

	serverField := v.FieldByName("Server")
	if serverField.IsValid() && serverField.Kind() == reflect.String {
		host = serverField.String()
	} else {
		serverOptionsField := v.FieldByName("ServerOptions")
		if serverOptionsField.IsValid() {
			if serverOptionsField.Kind() == reflect.Ptr {
				serverOptionsField = serverOptionsField.Elem()
			}
			if serverOptionsField.Kind() == reflect.Struct {
				hostField := serverOptionsField.FieldByName("Server")
				if hostField.IsValid() && hostField.Kind() == reflect.String {
					host = hostField.String()
				}
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
