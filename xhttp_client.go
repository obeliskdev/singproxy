package singproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const xhttpConnIdleTimeout = 300 * time.Second
const xhttpQuicgoH3KeepAlivePeriod = 10 * time.Second
const xhttpChromeH2KeepAlivePeriod = 45 * time.Second

type xhttpTransportMaker func() http.RoundTripper

type xhttpPacketUpWriter struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	cfg                  *xhttpConfig
	scMaxEachPostBytes   int
	scMinPostsIntervalMs xhttpRange
	sessionID            string
	transport            http.RoundTripper
	writeMu              sync.Mutex
	writeCond            sync.Cond
	seq                  uint64
	buf                  []byte
	timer                *time.Timer
	flushErr             error
	reqURL               string
	method               string
	discardBuf           []byte
}

func (c *xhttpPacketUpWriter) Write(b []byte) (int, error) {
	total := len(b)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.flushErr; err != nil {
		return 0, err
	}
	for len(b) > 0 {
		if c.timer == nil {
			c.timer = time.AfterFunc(time.Duration(c.scMinPostsIntervalMs.Rand())*time.Millisecond, c.flush)
		}
		room := c.scMaxEachPostBytes - len(c.buf)
		if room > 0 {
			if room > len(b) {
				room = len(b)
			}
			c.buf = append(c.buf, b[:room]...)
			b = b[room:]
		}
		if len(c.buf) >= c.scMaxEachPostBytes {
			c.writeCond.Wait()
			if err := c.flushErr; err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

func (c *xhttpPacketUpWriter) flush() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	defer c.writeCond.Broadcast()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if c.flushErr != nil || len(c.buf) == 0 {
		return
	}
	_, err := c.write(c.buf)
	c.buf = c.buf[:0]
	if err != nil {
		c.flushErr = err
	}
}

func (c *xhttpPacketUpWriter) write(b []byte) (int, error) {
	req, err := http.NewRequestWithContext(c.ctx, c.method, c.reqURL, nil)
	if err != nil {
		return 0, err
	}
	seqStr := strconv.FormatUint(c.seq, 10)
	c.seq++
	if err := c.cfg.fillPacketRequestHeaders(req.Header, req.URL, c.sessionID, seqStr, b); err != nil {
		return 0, err
	}
	req.Host = c.cfg.Host
	if placement := c.cfg.GetNormalizedUplinkDataPlacement(); placement == xhttpPlacementBody || placement == xhttpPlacementAuto {
		req.Body = io.NopCloser(bytes.NewReader(b))
		req.ContentLength = int64(len(b))
	}
	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.CopyBuffer(io.Discard, resp.Body, c.discardBuf)
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
	}
	return len(b), nil
}

func (c *xhttpPacketUpWriter) Close() error {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		c.flush()
	}()
	select {
	case <-ch:
	case <-time.After(time.Second):
	}
	c.cancel()
	xhttpCloseTransport(c.transport)
	return nil
}

type xhttpClient struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	mode                  string
	cfg                   *xhttpConfig
	scMaxEachPostBytes    xhttpRange
	scMinPostsIntervalMs  xhttpRange
	generateSessionID     func() string
	makeTransport         xhttpTransportMaker
	makeDownloadTransport xhttpTransportMaker
	uploadManager         *xhttpReuseManager
	downloadManager       *xhttpReuseManager
}

func newXhttpClient(cfg *xhttpConfig, makeTransport xhttpTransportMaker, makeDownloadTransport xhttpTransportMaker, hasReality bool) (*xhttpClient, error) {
	mode := cfg.EffectiveMode(hasReality)
	switch mode {
	case "stream-one", "stream-up", "packet-up":
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", mode)
	}
	scMaxEachPostBytes, err := cfg.GetNormalizedScMaxEachPostBytes()
	if err != nil {
		return nil, err
	}
	scMinPostsIntervalMs, err := cfg.GetNormalizedScMinPostsIntervalMs()
	if err != nil {
		return nil, err
	}
	generateSessionID, err := cfg.GetGenerateSessionID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	client := &xhttpClient{
		mode:                  mode,
		cfg:                   cfg,
		scMaxEachPostBytes:    scMaxEachPostBytes,
		scMinPostsIntervalMs:  scMinPostsIntervalMs,
		generateSessionID:     generateSessionID,
		makeTransport:         makeTransport,
		makeDownloadTransport: makeDownloadTransport,
		ctx:                   ctx,
		cancel:                cancel,
	}
	if cfg.ReuseConfig != nil {
		client.uploadManager, err = newXhttpReuseManager(cfg.ReuseConfig, makeTransport)
		if err != nil {
			return nil, err
		}
		client.makeTransport = client.uploadManager.GetTransport
		if cfg.DownloadConfig != nil {
			if makeDownloadTransport == nil {
				return nil, fmt.Errorf("xhttp: download manager requires download transport maker")
			}
			client.downloadManager, err = newXhttpReuseManager(cfg.DownloadConfig.ReuseConfig, makeDownloadTransport)
			if err != nil {
				return nil, err
			}
			client.makeDownloadTransport = client.downloadManager.GetTransport
		}
	}
	return client, nil
}

func (c *xhttpClient) Close() error {
	c.cancel()
	var errs []error
	if c.uploadManager != nil {
		errs = append(errs, c.uploadManager.Close())
	}
	if c.downloadManager != nil {
		errs = append(errs, c.downloadManager.Close())
	}
	return errors.Join(errs...)
}

func (c *xhttpClient) Dial(ctx context.Context) (net.Conn, error) {
	switch c.mode {
	case "stream-one":
		return c.dialStreamOne(ctx)
	case "stream-up":
		return c.dialStreamUp(ctx)
	case "packet-up":
		return c.dialPacketUp(ctx)
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", c.mode)
	}
}

type xhttpOnlyRoundTripper struct {
	http.RoundTripper
}

func (c *xhttpClient) getTransport() (uploadTransport http.RoundTripper, downloadTransport http.RoundTripper, err error) {
	uploadTransport = c.makeTransport()
	downloadTransport = xhttpOnlyRoundTripper{uploadTransport}
	if c.makeDownloadTransport != nil {
		downloadTransport = c.makeDownloadTransport()
	}
	return
}

func (c *xhttpClient) downloadConfig() *xhttpConfig {
	if ds := c.cfg.DownloadConfig; ds != nil {
		return ds
	}
	return c.cfg
}

func (c *xhttpClient) sendDownloadRequest(ctx context.Context, transport http.RoundTripper, dlCfg *xhttpConfig, sessionID string) (*http.Response, error) {
	downloadURL := url.URL{
		Scheme: "https",
		Host:   dlCfg.Host,
		Path:   dlCfg.NormalizedPath(),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if err := dlCfg.fillDownloadRequestHeaders(req.Header, req.URL, sessionID); err != nil {
		return nil, err
	}
	req.Host = dlCfg.Host
	return transport.RoundTrip(req)
}

func (c *xhttpClient) awaitDownload(ctx context.Context, transport http.RoundTripper, dlCfg *xhttpConfig, sessionID, modeLabel string) (*xhttpWaitReadCloser, chan error) {
	wrc := newXhttpWaitReadCloser()
	done := make(chan error, 1)

	go func() {
		resp, err := c.sendDownloadRequest(ctx, transport, dlCfg, sessionID)
		if err != nil {
			err = fmt.Errorf("xhttp %s download: %w", modeLabel, err)
			wrc.CloseWithError(err)
			done <- err
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			err = fmt.Errorf("xhttp %s download bad status: %s", modeLabel, resp.Status)
			wrc.CloseWithError(err)
			done <- err
			return
		}
		wrc.Set(resp.Body)
		done <- nil
	}()

	return wrc, done
}

func (c *xhttpClient) dialStreamOne(ctx context.Context) (net.Conn, error) {
	transport, _, err := c.getTransport()
	if err != nil {
		return nil, err
	}
	requestURL := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()
	conn := &xhttpConn{writer: pw}
	done := make(chan error, 1)
	reqCtx, reqCancel := context.WithCancel(c.ctx)
	// A POST whose body is a pipe blocks the transport write loop in
	// pipe.Read, and cancelling the request context does not unblock
	// it. Close the pipe with an error so RoundTrip can return when
	// the dial context expires or is cancelled.
	stop := context.AfterFunc(ctx, func() {
		reqCancel()
		_ = pw.CloseWithError(context.Canceled)
	})
	defer stop()

	go func() {
		req, err := http.NewRequestWithContext(reqCtx, c.cfg.GetNormalizedUplinkHTTPMethod(), requestURL.String(), pr)
		if err == nil {
			req.Host = c.cfg.Host
			err = c.cfg.fillStreamRequestHeaders(req.Header, req.URL, "", true)
		}
		var resp *http.Response
		if err == nil {
			resp, err = transport.RoundTrip(req)
		}
		if err != nil {
			_ = pw.CloseWithError(err)
			done <- fmt.Errorf("xhttp stream-one: %w", err)
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			err = fmt.Errorf("xhttp stream-one bad status: %s", resp.Status)
			_ = pw.CloseWithError(err)
			done <- err
			return
		}
		conn.reader = resp.Body
		conn.onClose = func() {
			_ = pr.Close()
			xhttpCloseTransport(transport)
			reqCancel()
		}
		done <- nil
	}()

	if err := <-done; err != nil {
		cleanupStreamOne(pr, pw, transport, reqCancel)
		return nil, err
	}
	return conn, nil
}

func cleanupStreamOne(pr *io.PipeReader, pw *io.PipeWriter, transport http.RoundTripper, cancel context.CancelFunc) {
	_ = pr.Close()
	_ = pw.Close()
	xhttpCloseTransport(transport)
	cancel()
}

func (c *xhttpClient) dialStreamUp(ctx context.Context) (net.Conn, error) {
	uploadTransport, downloadTransport, err := c.getTransport()
	if err != nil {
		return nil, err
	}
	dlCfg := c.downloadConfig()
	streamURL := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()
	conn := &xhttpConn{writer: pw}
	sessionID := c.generateSessionID()
	reqCtx, reqCancel := context.WithCancel(c.ctx)
	// Closing the pipe unblocks the transport write loop when the dial
	// context expires; see the matching comment in dialStreamOne.
	stop := context.AfterFunc(ctx, func() {
		reqCancel()
		_ = pw.CloseWithError(context.Canceled)
	})
	defer stop()

	uploadReq, err := http.NewRequestWithContext(reqCtx, c.cfg.GetNormalizedUplinkHTTPMethod(), streamURL.String(), pr)
	if err != nil {
		cleanupStreamUp(uploadTransport, downloadTransport, reqCancel)
		return nil, err
	}
	if err = c.cfg.fillStreamRequestHeaders(uploadReq.Header, uploadReq.URL, sessionID, true); err != nil {
		cleanupStreamUp(uploadTransport, downloadTransport, reqCancel)
		return nil, err
	}
	uploadReq.Host = c.cfg.Host

	wrc, dlDone := c.awaitDownload(reqCtx, downloadTransport, dlCfg, sessionID, "stream-up")

	if dlErr := <-dlDone; dlErr != nil {
		cleanupStreamUp(uploadTransport, downloadTransport, reqCancel)
		return nil, dlErr
	}

	conn.reader = wrc
	conn.onClose = func() {
		_ = pr.Close()
		xhttpCloseTransport(uploadTransport)
		xhttpCloseTransport(downloadTransport)
		reqCancel()
	}

	go func() {
		resp, err := uploadTransport.RoundTrip(uploadReq)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = pw.CloseWithError(fmt.Errorf("xhttp stream-up upload bad status: %s", resp.Status))
		}
	}()

	return conn, nil
}

func cleanupStreamUp(uploadTransport, downloadTransport http.RoundTripper, cancel context.CancelFunc) {
	xhttpCloseTransport(uploadTransport)
	xhttpCloseTransport(downloadTransport)
	cancel()
}

func (c *xhttpClient) dialPacketUp(ctx context.Context) (net.Conn, error) {
	uploadTransport, downloadTransport, err := c.getTransport()
	if err != nil {
		return nil, err
	}
	dlCfg := c.downloadConfig()
	sessionID := c.generateSessionID()
	writerCtx, writerCancel := context.WithCancel(c.ctx)
	scMax := c.scMaxEachPostBytes.Rand()
	writer := &xhttpPacketUpWriter{
		ctx:                  writerCtx,
		cancel:               writerCancel,
		cfg:                  c.cfg,
		scMaxEachPostBytes:   scMax,
		scMinPostsIntervalMs: c.scMinPostsIntervalMs,
		sessionID:            sessionID,
		transport:            uploadTransport,
		reqURL: (&url.URL{
			Scheme: "https",
			Host:   c.cfg.Host,
			Path:   c.cfg.NormalizedPath(),
		}).String(),
		method:     c.cfg.GetNormalizedUplinkHTTPMethod(),
		buf:        make([]byte, 0, scMax),
		discardBuf: make([]byte, 8*1024),
	}
	writer.writeCond = sync.Cond{L: &writer.writeMu}
	conn := &xhttpConn{writer: writer}
	reqCtx, reqCancel := context.WithCancel(c.ctx)
	stop := context.AfterFunc(ctx, reqCancel)
	defer stop()

	wrc, dlDone := c.awaitDownload(reqCtx, downloadTransport, dlCfg, sessionID, "packet-up")

	if dlErr := <-dlDone; dlErr != nil {
		xhttpCloseTransport(uploadTransport)
		xhttpCloseTransport(downloadTransport)
		reqCancel()
		return nil, dlErr
	}

	conn.reader = wrc
	conn.onClose = func() {
		xhttpCloseTransport(downloadTransport)
		reqCancel()
	}

	return conn, nil
}

func newXhttpTransport(tlsCfg *xhttpTLSConfig, alpn []string, keepAlivePeriod time.Duration, dialRaw func(ctx context.Context) (net.Conn, error)) (http.RoundTripper, error) {
	if len(alpn) == 1 && alpn[0] == "h3" {
		return newXhttpH3Transport(tlsCfg, keepAlivePeriod, dialRaw)
	}

	dialTLS := func(isH2 bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dialRaw(ctx)
			if err != nil {
				return nil, err
			}
			if tlsCfg == nil {
				return raw, nil
			}
			wrapped, err := tlsCfg.WrapConn(ctx, raw, isH2)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return wrapped, nil
		}
	}

	if len(alpn) == 1 && alpn[0] == "http/1.1" {
		return &http.Transport{
			DialContext:       dialTLS(false),
			DialTLSContext:    dialTLS(false),
			IdleConnTimeout:   xhttpConnIdleTimeout,
			ForceAttemptHTTP2: false,
		}, nil
	}

	if tlsCfg != nil && tlsCfg.forceH2C {
		// uTLS connections are not *tls.Conn, and net/http has no way to
		// detect the ALPN-negotiated HTTP/2 for custom TLS dialers. Speak
		// HTTP/2 framing directly over the already-encrypted connection
		// (h2c-style), as mihomo does with its net/http fork.
		protocols := new(http.Protocols)
		protocols.SetUnencryptedHTTP2(true)
		protocols.SetHTTP1(false)
		return &http.Transport{
			DialTLSContext:  dialTLS(true),
			IdleConnTimeout: xhttpConnIdleTimeout,
			Protocols:       protocols,
		}, nil
	}

	if keepAlivePeriod == 0 {
		keepAlivePeriod = xhttpChromeH2KeepAlivePeriod
	}
	if keepAlivePeriod < 0 {
		keepAlivePeriod = 0
	}
	transport := &http.Transport{
		DialTLSContext:    dialTLS(true),
		IdleConnTimeout:   xhttpConnIdleTimeout,
		ForceAttemptHTTP2: true,
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("xhttp: failed to configure h2: %w", err)
	}
	return transport, nil
}
