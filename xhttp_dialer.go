package singproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func parseXHTTPTransportParams(params url.Values, server string, port int) (*xhttpConfig, error) {
	serverAddress := net.JoinHostPort(server, strconv.Itoa(port))
	tlsPrm := parseTLSParams(params, serverAddress)

	cfg := &xhttpConfig{
		Host:             params.Get("host"),
		Path:             params.Get("path"),
		Mode:             params.Get("mode"),
		NoGRPCHeader:     parseBool(params.Get("noGRPCHeader")),
		XPaddingBytes:    params.Get("xPaddingBytes"),
		UplinkHTTPMethod: params.Get("upstreamMethod"),
	}
	if cfg.Host == "" {
		cfg.Host = serverAddress
	}
	for k, vs := range params {
		if strings.HasPrefix(k, "header_") {
			if cfg.Headers == nil {
				cfg.Headers = make(map[string]string)
			}
			if len(vs) > 0 {
				cfg.Headers[strings.TrimPrefix(k, "header_")] = vs[0]
			}
		}
	}

	if tlsPrm.enabled {
		ctx := context.Background()
		tlsCfg, err := newXHTTPTLSConfig(ctx, tlsPrm)
		if err != nil {
			return nil, fmt.Errorf("xhttp tls: %w", err)
		}
		cfg.TLSConfig = tlsCfg
	}

	if muxStr := params.Get("xmux"); muxStr != "" {
		cfg.ReuseConfig = parseXHTTPReuseConfig(muxStr)
	}
	if v := params.Get("scMaxEachPostBytes"); v != "" {
		cfg.ScMaxEachPostBytes = v
	}
	if v := params.Get("scMinPostsIntervalMs"); v != "" {
		cfg.ScMinPostsIntervalMs = v
	}

	if dl := params.Get("downloadSettings"); dl != "" {
		dlParams, err := parseDownloadSettings(dl, server, port)
		if err != nil {
			return nil, fmt.Errorf("xhttp downloadSettings: %w", err)
		}
		cfg.DownloadConfig = dlParams
	}

	return cfg, nil
}

func parseDownloadSettings(dl string, server string, port int) (*xhttpConfig, error) {
	vals, err := url.ParseQuery(dl)
	if err != nil {
		return nil, fmt.Errorf("parse downloadSettings query: %w", err)
	}
	dlServer := vals.Get("address")
	if dlServer == "" {
		dlServer = server
	}
	dlPort := vals.Get("port")
	if dlPort == "" {
		dlPort = strconv.Itoa(port)
	}
	dlPortInt, err := strconv.Atoi(dlPort)
	if err != nil {
		return nil, fmt.Errorf("downloadSettings port: %w", err)
	}
	dlParams := url.Values{}
	for k, vs := range vals {
		for _, v := range vs {
			dlParams.Add(k, v)
		}
	}
	dlParams.Set("host", vals.Get("host"))
	dlParams.Set("path", vals.Get("path"))
	dlParams.Set("mode", vals.Get("mode"))
	return parseXHTTPTransportParams(dlParams, dlServer, dlPortInt)
}

func parseXHTTPReuseConfig(s string) *xhttpReuseConfig {
	cfg := &xhttpReuseConfig{}
	for _, part := range strings.Split(s, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		switch key {
		case "maxConcurrency":
			cfg.MaxConcurrency = value
		case "maxConnections":
			cfg.MaxConnections = value
		case "cMaxReuseTimes":
			cfg.CMaxReuseTimes = value
		case "hMaxRequestTimes":
			cfg.HMaxRequestTimes = value
		case "hMaxReusableSecs":
			cfg.HMaxReusableSecs = value
		}
	}
	return cfg
}

func makeTransportMaker(tlsCfg *xhttpTLSConfig, server string, port int, dialTimeout time.Duration) xhttpTransportMaker {
	dialRaw := func(ctx context.Context) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: dialTimeout}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(server, strconv.Itoa(port)))
	}
	var alpn []string
	if tlsCfg != nil {
		alpn = tlsCfg.alpn
	}
	return func() http.RoundTripper {
		tr, err := newXhttpTransport(tlsCfg, alpn, 0, dialRaw)
		if err != nil {
			return nil
		}
		return tr
	}
}

func dialXHTTP(ctx context.Context, cfg *xhttpConfig, server string, port int, pcfg Config) (net.Conn, error) {
	hasReality := cfg.TLSConfig != nil && cfg.TLSConfig.isReality

	transportMaker := makeTransportMaker(cfg.TLSConfig, server, port, pcfg.XHTTPDialTimeout)

	var downloadTransportMaker xhttpTransportMaker
	if cfg.DownloadConfig != nil {
		dlServer := server
		dlPort := port
		if cfg.DownloadConfig.Host != "" {
			if h, p, err := net.SplitHostPort(cfg.DownloadConfig.Host); err == nil {
				dlServer = h
				if p != "" {
					if portInt, err := strconv.Atoi(p); err == nil {
						dlPort = portInt
					}
				}
			}
		}
		downloadTransportMaker = makeTransportMaker(cfg.DownloadConfig.TLSConfig, dlServer, dlPort, pcfg.XHTTPDialTimeout)
	}

	client, err := newXhttpClient(cfg, transportMaker, downloadTransportMaker, hasReality)
	if err != nil {
		return nil, fmt.Errorf("xhttp client: %w", err)
	}

	conn, err := client.Dial(ctx)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("xhttp dial: %w", err)
	}

	return conn, nil
}
