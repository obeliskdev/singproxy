package singproxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestXHTTPRangeRandBounds(t *testing.T) {
	r := xhttpRange{Min: 0, Max: 0}
	if v := r.Rand(); v != 0 {
		t.Errorf("Rand({0,0}) = %d, want 0", v)
	}
	r = xhttpRange{Min: 1, Max: 100}
	for i := 0; i < 1000; i++ {
		v := r.Rand()
		if v < 1 || v > 100 {
			t.Fatalf("Rand({1,100}) = %d, out of range", v)
		}
	}
}

func TestXHTTPParseRangeWhitespace(t *testing.T) {
	r, err := xhttpParseRange("  100 - 200  ", "0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Min != 100 || r.Max != 200 {
		t.Errorf("got {%d,%d}, want {100,200}", r.Min, r.Max)
	}
}

func TestXHTTPParseRangeEmptyFallback(t *testing.T) {
	r, err := xhttpParseRange("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Min != 0 || r.Max != 0 {
		t.Errorf("got {%d,%d}, want {0,0}", r.Min, r.Max)
	}
}

func TestXHTTPParseRangeTooManyParts(t *testing.T) {
	_, err := xhttpParseRange("1-2-3", "0")
	if err == nil {
		t.Fatal("expected error for 3-part range")
	}
}

func TestXHTTPParseRangeNegativeMin(t *testing.T) {
	_, err := xhttpParseRange("-5-10", "0")
	if err == nil {
		t.Fatal("expected error for negative min")
	}
}

func TestXHTTPReuseConfigResolveNil(t *testing.T) {
	var cfg *xhttpReuseConfig
	conc, conn, err := cfg.resolveManagerConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conc.Min != 0 || conc.Max != 0 {
		t.Errorf("concurrency = {%d,%d}, want {0,0}", conc.Min, conc.Max)
	}
	if conn.Min != 0 || conn.Max != 0 {
		t.Errorf("connections = {%d,%d}, want {0,0}", conn.Min, conn.Max)
	}
}

func TestXHTTPReuseConfigResolveEntryNil(t *testing.T) {
	var cfg *xhttpReuseConfig
	reuse, req, secs, err := cfg.resolveEntryConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reuse.Min != 0 || req.Min != 0 || secs.Min != 0 {
		t.Errorf("expected all zeros")
	}
}

func TestXHTTPReuseConfigResolveInvalid(t *testing.T) {
	cfg := &xhttpReuseConfig{MaxConcurrency: "abc"}
	_, _, err := cfg.resolveManagerConfig()
	if err == nil {
		t.Fatal("expected error for invalid maxConcurrency")
	}
}

func TestXHTTPReuseConfigResolveEntryInvalid(t *testing.T) {
	cfg := &xhttpReuseConfig{CMaxReuseTimes: "xyz"}
	_, _, _, err := cfg.resolveEntryConfig()
	if err == nil {
		t.Fatal("expected error for invalid cMaxReuseTimes")
	}
}

func TestXHTTPConfigNormalizedMode(t *testing.T) {
	c := &xhttpConfig{}
	if got := c.NormalizedMode(); got != "auto" {
		t.Errorf("NormalizedMode() = %q, want auto", got)
	}
	c.Mode = "stream-up"
	if got := c.NormalizedMode(); got != "stream-up" {
		t.Errorf("NormalizedMode() = %q, want stream-up", got)
	}
}

func TestXHTTPConfigScMinPostsIntervalMs(t *testing.T) {
	c := &xhttpConfig{}
	r, err := c.GetNormalizedScMinPostsIntervalMs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Min != 30 || r.Max != 30 {
		t.Errorf("default = {%d,%d}, want {30,30}", r.Min, r.Max)
	}
	c.ScMinPostsIntervalMs = "10-50"
	r, err = c.GetNormalizedScMinPostsIntervalMs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Min != 10 || r.Max != 50 {
		t.Errorf("got {%d,%d}, want {10,50}", r.Min, r.Max)
	}
}

func TestXHTTPConfigScMaxEachPostBytesZero(t *testing.T) {
	c := &xhttpConfig{ScMaxEachPostBytes: "0"}
	_, err := c.GetNormalizedScMaxEachPostBytes()
	if err == nil {
		t.Fatal("expected error for zero max")
	}
}

func TestXHTTPConfigScMinPostsIntervalMsZero(t *testing.T) {
	c := &xhttpConfig{ScMinPostsIntervalMs: "0"}
	_, err := c.GetNormalizedScMinPostsIntervalMs()
	if err == nil {
		t.Fatal("expected error for zero max")
	}
}

func TestXHTTPConfigUplinkDataPlacement(t *testing.T) {
	c := &xhttpConfig{}
	if got := c.GetNormalizedUplinkDataPlacement(); got != xhttpPlacementBody {
		t.Errorf("default = %q, want %q", got, xhttpPlacementBody)
	}
	c.UplinkDataPlacement = xhttpPlacementHeader
	if got := c.GetNormalizedUplinkDataPlacement(); got != xhttpPlacementHeader {
		t.Errorf("got %q, want %q", got, xhttpPlacementHeader)
	}
}

func TestXHTTPConfigUplinkChunkSizeDefault(t *testing.T) {
	c := &xhttpConfig{}
	r, err := c.GetNormalizedUplinkChunkSize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Min != 1000000 || r.Max != 1000000 {
		t.Errorf("default body chunk = {%d,%d}, want {1000000,1000000}", r.Min, r.Max)
	}
}

func TestXHTTPConfigUplinkChunkSizeCookie(t *testing.T) {
	c := &xhttpConfig{UplinkDataPlacement: xhttpPlacementCookie}
	r, err := c.GetNormalizedUplinkChunkSize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Min != 2048 || r.Max != 3072 {
		t.Errorf("cookie chunk = {%d,%d}, want {2048,3072}", r.Min, r.Max)
	}
}

func TestXHTTPConfigUplinkChunkSizeHeader(t *testing.T) {
	c := &xhttpConfig{UplinkDataPlacement: xhttpPlacementHeader}
	r, err := c.GetNormalizedUplinkChunkSize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Min != 3072 || r.Max != 4096 {
		t.Errorf("header chunk = {%d,%d}, want {3072,4096}", r.Min, r.Max)
	}
}

func TestXHTTPConfigUplinkChunkSizeMinClamp(t *testing.T) {
	c := &xhttpConfig{UplinkChunkSize: "10-20"}
	r, err := c.GetNormalizedUplinkChunkSize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Min != 64 || r.Max != 64 {
		t.Errorf("clamped chunk = {%d,%d}, want {64,64}", r.Min, r.Max)
	}
}

func TestXHTTPConfigSessionKeyCustom(t *testing.T) {
	c := &xhttpConfig{SessionPlacement: xhttpPlacementHeader, SessionKey: "X-MySession"}
	if got := c.GetNormalizedSessionKey(); got != "X-MySession" {
		t.Errorf("custom session key = %q, want X-MySession", got)
	}
}

func TestXHTTPConfigSeqKeyCustom(t *testing.T) {
	c := &xhttpConfig{SeqPlacement: xhttpPlacementQuery, SeqKey: "my_seq"}
	if got := c.GetNormalizedSeqKey(); got != "my_seq" {
		t.Errorf("custom seq key = %q, want my_seq", got)
	}
}

func TestXHTTPConfigSessionKeyPathDefault(t *testing.T) {
	c := &xhttpConfig{}
	if got := c.GetNormalizedSessionKey(); got != "" {
		t.Errorf("path session key = %q, want empty", got)
	}
}

func TestXHTTPConfigSeqKeyPathDefault(t *testing.T) {
	c := &xhttpConfig{}
	if got := c.GetNormalizedSeqKey(); got != "" {
		t.Errorf("path seq key = %q, want empty", got)
	}
}

func TestXHTTPConfigGenerateSessionIDPredefined(t *testing.T) {
	c := &xhttpConfig{SessionTable: "hex", SessionLength: "8-8"}
	gen, err := c.GetGenerateSessionID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	id := gen()
	if len(id) != 8 {
		t.Errorf("session ID length = %d, want 8", len(id))
	}
	for _, ch := range id {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			t.Errorf("session ID contains non-hex char: %c", ch)
			break
		}
	}
}

func TestXHTTPConfigGenerateSessionIDTooSmall(t *testing.T) {
	c := &xhttpConfig{SessionTable: "number", SessionLength: "1-1"}
	_, err := c.GetGenerateSessionID()
	if err == nil {
		t.Fatal("expected error for too-small session space")
	}
}

func TestXHTTPConfigGenerateSessionIDNonASCII(t *testing.T) {
	c := &xhttpConfig{SessionTable: "abcdefghijklmnopqrstuvwxyzæøå", SessionLength: "16-32"}
	_, err := c.GetGenerateSessionID()
	if err == nil {
		t.Fatal("expected error for non-ASCII session table")
	}
}

func TestXHTTPConfigGenerateSessionIDInvalidLength(t *testing.T) {
	c := &xhttpConfig{SessionTable: "hex", SessionLength: "abc"}
	_, err := c.GetGenerateSessionID()
	if err == nil {
		t.Fatal("expected error for invalid session length")
	}
}

func TestXHTTPAppendToPath(t *testing.T) {
	tests := []struct {
		path  string
		value string
		want  string
	}{
		{"/foo/", "bar", "/foo/bar"},
		{"/foo", "bar", "/foo/bar"},
		{"/", "abc", "/abc"},
		{"", "x", "/x"},
	}
	for _, tc := range tests {
		got := xhttpAppendToPath(tc.path, tc.value)
		if got != tc.want {
			t.Errorf("appendToPath(%q, %q) = %q, want %q", tc.path, tc.value, got, tc.want)
		}
	}
}

func TestXHTTPRoomSize(t *testing.T) {
	r := xhttpRoomSize(16, 1, 1)
	expected := int64(16)
	if r.Int64() != expected {
		t.Errorf("roomSize(16,1,1) = %d, want %d", r.Int64(), expected)
	}
	r = xhttpRoomSize(2, 1, 3)
	expected = int64(2 + 4 + 8)
	if r.Int64() != expected {
		t.Errorf("roomSize(2,1,3) = %d, want %d", r.Int64(), expected)
	}
}

func TestXHTTPConnReadWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	conn := &xhttpConn{
		writer: c2,
		reader: c2,
	}
	defer conn.Close()

	go func() {
		_, _ = c1.Write([]byte("hello"))
	}()

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil || n != 5 || string(buf) != "hello" {
		t.Fatalf("Read: n=%d err=%v data=%q", n, err, string(buf))
	}

	go func() {
		_, _ = c1.Read(make([]byte, 5))
	}()

	n, err = conn.Write([]byte("world"))
	if err != nil || n != 5 {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
}

func TestXHTTPConnCloseCallback(t *testing.T) {
	c1, c2 := net.Pipe()
	called := false
	conn := &xhttpConn{
		writer:  c2,
		reader:  c2,
		onClose: func() { called = true },
	}
	_ = conn.Close()
	_ = c1.Close()
	if !called {
		t.Error("onClose callback was not called")
	}
}

func TestXHTTPConnDeadline(t *testing.T) {
	c1, c2 := net.Pipe()
	conn := &xhttpConn{
		writer: c2,
		reader: c2,
	}
	defer conn.Close()
	_ = c1.Close()

	err := conn.SetDeadline(time.Now().Add(50 * time.Millisecond))
	if err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected error after deadline")
	}
}

func TestXHTTPConnClearDeadline(t *testing.T) {
	c1, c2 := net.Pipe()
	conn := &xhttpConn{
		writer: c2,
		reader: c2,
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Millisecond))
	_ = conn.SetDeadline(time.Time{})

	// If clear worked, the conn should still be alive after the original deadline
	time.Sleep(30 * time.Millisecond)

	// Write should still work (conn not closed by old deadline)
	go func() {
		_, _ = c1.Read(make([]byte, 5))
	}()
	n, err := conn.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write after cleared deadline: n=%d err=%v", n, err)
	}
	_ = c1.Close()
}

func TestXHTTPConnLocalRemoteAddr(t *testing.T) {
	c1, c2 := net.Pipe()
	localAddr := &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 5678}
	conn := &xhttpConn{
		writer:     c2,
		reader:     c2,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	defer conn.Close()
	_ = c1.Close()

	if conn.LocalAddr().String() != localAddr.String() {
		t.Errorf("LocalAddr = %v, want %v", conn.LocalAddr(), localAddr)
	}
	if conn.RemoteAddr().String() != remoteAddr.String() {
		t.Errorf("RemoteAddr = %v, want %v", conn.RemoteAddr(), remoteAddr)
	}
}

func TestXHTTPWaitReadCloserSet(t *testing.T) {
	wrc := newXhttpWaitReadCloser()
	go func() {
		time.Sleep(10 * time.Millisecond)
		wrc.Set(io.NopCloser(strings.NewReader("data")))
	}()

	buf := make([]byte, 4)
	n, err := wrc.Read(buf)
	if err != nil || n != 4 || string(buf) != "data" {
		t.Fatalf("Read: n=%d err=%v data=%q", n, err, string(buf))
	}
}

func TestXHTTPWaitReadCloserError(t *testing.T) {
	wrc := newXhttpWaitReadCloser()
	testErr := errors.New("test error")
	go func() {
		time.Sleep(10 * time.Millisecond)
		wrc.CloseWithError(testErr)
	}()

	buf := make([]byte, 4)
	_, err := wrc.Read(buf)
	if !errors.Is(err, testErr) {
		t.Fatalf("Read error = %v, want %v", err, testErr)
	}
}

func TestXHTTPWaitReadCloserCloseTwice(t *testing.T) {
	wrc := newXhttpWaitReadCloser()
	_ = wrc.Close()
	_ = wrc.Close()
	buf := make([]byte, 1)
	_, err := wrc.Read(buf)
	if err == nil {
		t.Error("expected error after close")
	}
}

func TestXHTTPWaitReadCloserSetAfterClose(t *testing.T) {
	wrc := newXhttpWaitReadCloser()
	_ = wrc.Close()
	rc := io.NopCloser(strings.NewReader("test"))
	wrc.Set(rc)
}

func TestXHTTPReuseManagerNil(t *testing.T) {
	var m *xhttpReuseManager
	if err := m.Close(); err != nil {
		t.Errorf("Close() on nil manager: %v", err)
	}
}

func TestXHTTPReuseManagerCreateAndGet(t *testing.T) {
	cfg := &xhttpReuseConfig{
		MaxConcurrency: "2",
		MaxConnections: "3",
	}
	maker := func() http.RoundTripper {
		return &mockRoundTripper{}
	}
	m, err := newXhttpReuseManager(cfg, maker)
	if err != nil {
		t.Fatalf("newXhttpReuseManager: %v", err)
	}
	if m == nil {
		t.Fatal("manager is nil")
	}
	if m.maxConcurrency != 2 {
		t.Errorf("maxConcurrency = %d, want 2", m.maxConcurrency)
	}
	if m.maxConnections != 3 {
		t.Errorf("maxConnections = %d, want 3", m.maxConnections)
	}

	tr1 := m.GetTransport()
	if tr1 == nil {
		t.Fatal("GetTransport returned nil")
	}
	tr2 := m.GetTransport()
	if tr2 == nil {
		t.Fatal("second GetTransport returned nil")
	}

	_ = m.Close()
}

func TestXHTTPReuseManagerNilConfig(t *testing.T) {
	m, err := newXhttpReuseManager(nil, func() http.RoundTripper { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Fatal("expected nil manager for nil config")
	}
}

func TestXHTTPReuseEntryRelease(t *testing.T) {
	entry := &xhttpReuseEntry{
		transport: &mockRoundTripper{},
	}
	entry.openUsage.Store(1)
	entry.release()
	if entry.openUsage.Load() != 0 {
		t.Errorf("openUsage after release = %d, want 0", entry.openUsage.Load())
	}
}

func TestXHTTPReuseEntryReleaseNegative(t *testing.T) {
	entry := &xhttpReuseEntry{}
	entry.openUsage.Store(-1)
	entry.release()
	if entry.openUsage.Load() != 0 {
		t.Errorf("openUsage after negative release = %d, want 0", entry.openUsage.Load())
	}
}

func TestXHTTPReuseEntryCloseTwice(t *testing.T) {
	entry := &xhttpReuseEntry{transport: &mockRoundTripper{}}
	entry.close()
	entry.close()
	if !entry.isClosed() {
		t.Error("entry should be closed")
	}
}

func TestXHTTPReuseTransportCloseTwice(t *testing.T) {
	entry := &xhttpReuseEntry{transport: &mockRoundTripper{}}
	rt := &xhttpReuseTransport{entry: entry}
	_ = rt.Close()
	_ = rt.Close()
}

func TestXHTTPCloseTransport(t *testing.T) {
	mrt := &mockRoundTripper{}
	xhttpCloseTransport(mrt)
	if !mrt.closedIdle {
		t.Error("CloseIdleConnections not called")
	}
}

func TestXHTTPCloseTransportCloser(t *testing.T) {
	mc := &mockCloserRoundTripper{}
	xhttpCloseTransport(mc)
	if !mc.closed {
		t.Error("Close not called")
	}
}

func TestXHTTPParseTransportParamsHeaders(t *testing.T) {
	params := url.Values{
		"type":            {"xhttp"},
		"path":            {"/xh"},
		"header_X-Custom": {"custom-value"},
	}
	cfg, err := parseXHTTPTransportParams(params, "host.example.com", 443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Headers == nil {
		t.Fatal("Headers is nil")
	}
	if v, ok := cfg.Headers["X-Custom"]; !ok || v != "custom-value" {
		t.Errorf("Headers[X-Custom] = %q, ok=%v", v, ok)
	}
}

func TestXHTTPParseTransportParamsXMux(t *testing.T) {
	params := url.Values{
		"type": {"xhttp"},
		"xmux": {"maxConcurrency=16,maxConnections=4"},
	}
	cfg, err := parseXHTTPTransportParams(params, "host.example.com", 443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ReuseConfig == nil {
		t.Fatal("ReuseConfig is nil")
	}
	if cfg.ReuseConfig.MaxConcurrency != "16" {
		t.Errorf("MaxConcurrency = %q", cfg.ReuseConfig.MaxConcurrency)
	}
}

func TestXHTTPParseTransportParamsScParams(t *testing.T) {
	params := url.Values{
		"type":                 {"xhttp"},
		"scMaxEachPostBytes":   {"500000"},
		"scMinPostsIntervalMs": {"50"},
	}
	cfg, err := parseXHTTPTransportParams(params, "host.example.com", 443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ScMaxEachPostBytes != "500000" {
		t.Errorf("ScMaxEachPostBytes = %q", cfg.ScMaxEachPostBytes)
	}
	if cfg.ScMinPostsIntervalMs != "50" {
		t.Errorf("ScMinPostsIntervalMs = %q", cfg.ScMinPostsIntervalMs)
	}
}

func TestXHTTPParseTransportParamsNoTLS(t *testing.T) {
	params := url.Values{
		"type": {"xhttp"},
		"path": {"/xh"},
	}
	cfg, err := parseXHTTPTransportParams(params, "host.example.com", 443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TLSConfig != nil {
		t.Fatal("TLSConfig should be nil when no TLS params")
	}
}

func TestXHTTPParseDownloadSettingsDefaults(t *testing.T) {
	dlQuery := "path=/dl"
	params := url.Values{
		"type":             {"xhttp"},
		"path":             {"/ul"},
		"downloadSettings": {dlQuery},
	}
	cfg, err := parseXHTTPTransportParams(params, "host.example.com", 443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DownloadConfig == nil {
		t.Fatal("DownloadConfig is nil")
	}
	if cfg.DownloadConfig.Path != "/dl" {
		t.Errorf("download path = %q, want /dl", cfg.DownloadConfig.Path)
	}
}

func TestXHTTPParseDownloadSettingsInvalidPort(t *testing.T) {
	dlQuery := "address=dl.example.com&port=abc"
	params := url.Values{
		"type":             {"xhttp"},
		"downloadSettings": {dlQuery},
	}
	_, err := parseXHTTPTransportParams(params, "host.example.com", 443)
	if err == nil {
		t.Fatal("expected error for invalid download port")
	}
}

func TestXHTTPParseReuseConfigAllFields(t *testing.T) {
	cfg := parseXHTTPReuseConfig("maxConcurrency=16,maxConnections=4,cMaxReuseTimes=100,hMaxRequestTimes=600,hMaxReusableSecs=1800")
	if cfg.MaxConcurrency != "16" {
		t.Errorf("MaxConcurrency = %q", cfg.MaxConcurrency)
	}
	if cfg.MaxConnections != "4" {
		t.Errorf("MaxConnections = %q", cfg.MaxConnections)
	}
	if cfg.CMaxReuseTimes != "100" {
		t.Errorf("CMaxReuseTimes = %q", cfg.CMaxReuseTimes)
	}
	if cfg.HMaxRequestTimes != "600" {
		t.Errorf("HMaxRequestTimes = %q", cfg.HMaxRequestTimes)
	}
	if cfg.HMaxReusableSecs != "1800" {
		t.Errorf("HMaxReusableSecs = %q", cfg.HMaxReusableSecs)
	}
}

func TestXHTTPParseReuseConfigGarbage(t *testing.T) {
	cfg := parseXHTTPReuseConfig("garbage,notkeyval,=,key=")
	if cfg.MaxConcurrency != "" {
		t.Errorf("MaxConcurrency = %q, want empty", cfg.MaxConcurrency)
	}
}

func TestXHTTPParseReuseConfigEmpty(t *testing.T) {
	cfg := parseXHTTPReuseConfig("")
	if cfg.MaxConcurrency != "" {
		t.Errorf("MaxConcurrency = %q, want empty", cfg.MaxConcurrency)
	}
}

func TestXHTTPPaddingTokenish(t *testing.T) {
	s := xhttpGeneratePadding(xhttpPaddingMethodTokenish, 100)
	if s == "" {
		t.Fatal("tokenish padding is empty")
	}
	if len(s) < 50 {
		t.Errorf("tokenish padding too short: %d", len(s))
	}
}

func TestXHTTPPaddingNegativeLength(t *testing.T) {
	s := xhttpGeneratePadding(xhttpPaddingMethodRepeatX, -1)
	if s != "" {
		t.Errorf("negative length padding = %q, want empty", s)
	}
}

func TestXHTTPPaddingUnknownMethod(t *testing.T) {
	s := xhttpGeneratePadding("unknown", 50)
	if len(s) != 50 {
		t.Errorf("unknown method padding length = %d, want 50", len(s))
	}
	for _, c := range s {
		if c != 'X' {
			t.Error("unknown method should default to repeat-X")
			break
		}
	}
}

func TestXHTTPRandStringFromCharset(t *testing.T) {
	s, ok := xhttpRandStringFromCharset(10, "abcdef")
	if !ok {
		t.Fatal("randStringFromCharset returned false")
	}
	if len(s) != 10 {
		t.Fatalf("length = %d, want 10", len(s))
	}
	for _, c := range s {
		if !strings.ContainsRune("abcdef", c) {
			t.Errorf("char %c not in charset", c)
			break
		}
	}
}

func TestXHTTPRandStringFromCharsetZero(t *testing.T) {
	_, ok := xhttpRandStringFromCharset(0, "abc")
	if ok {
		t.Error("expected false for n=0")
	}
}

func TestXHTTPRandStringFromCharsetEmpty(t *testing.T) {
	_, ok := xhttpRandStringFromCharset(10, "")
	if ok {
		t.Error("expected false for empty charset")
	}
}

func TestXHTTPAbsInt(t *testing.T) {
	if xhttpAbsInt(-5) != 5 {
		t.Error("abs(-5) = 5")
	}
	if xhttpAbsInt(5) != 5 {
		t.Error("abs(5) = 5")
	}
	if xhttpAbsInt(0) != 0 {
		t.Error("abs(0) = 0")
	}
}

func TestXHTTPBase64URLEncode(t *testing.T) {
	result := xhttpBase64URLEncode([]byte("hello"))
	if result != "aGVsbG8" {
		t.Errorf("base64URLEncode = %q, want aGVsbG8", result)
	}
}

func TestXHTTPApplyXPaddingToHeader(t *testing.T) {
	h := http.Header{}
	c := &xhttpConfig{}
	config := xhttpPaddingConfig{
		Length: 10,
		Placement: xhttpPaddingPlacement{
			Placement: xhttpPlacementHeader,
			Header:    "X-Padding",
		},
		Method: xhttpPaddingMethodRepeatX,
	}
	c.applyXPaddingToHeader(h, config)
	if h.Get("X-Padding") != "XXXXXXXXXX" {
		t.Errorf("X-Padding = %q, want XXXXXXXXXX", h.Get("X-Padding"))
	}
}

func TestXHTTPApplyXPaddingToHeaderNil(t *testing.T) {
	c := &xhttpConfig{}
	c.applyXPaddingToHeader(nil, xhttpPaddingConfig{Length: 10})
}

func TestXHTTPApplyXPaddingToRequestQuery(t *testing.T) {
	h := http.Header{}
	u, _ := url.Parse("https://example.com/path")
	c := &xhttpConfig{}
	config := xhttpPaddingConfig{
		Length: 5,
		Placement: xhttpPaddingPlacement{
			Placement: xhttpPlacementQuery,
			Key:       "pad",
		},
		Method: xhttpPaddingMethodRepeatX,
	}
	c.applyXPaddingToRequest(h, u, config)
	if u.Query().Get("pad") != "XXXXX" {
		t.Errorf("query pad = %q, want XXXXX", u.Query().Get("pad"))
	}
}

func TestXHTTPFillStreamRequestHeaders(t *testing.T) {
	h := http.Header{}
	u, _ := url.Parse("https://example.com/path")
	c := &xhttpConfig{}
	err := c.fillStreamRequestHeaders(h, u, "session123", true)
	if err != nil {
		t.Fatalf("fillStreamRequestHeaders: %v", err)
	}
	if h.Get("Content-Type") != "application/grpc" {
		t.Errorf("Content-Type = %q, want application/grpc", h.Get("Content-Type"))
	}
	if h.Get("User-Agent") == "" {
		t.Error("User-Agent should be set by masquerade")
	}
	if !strings.Contains(u.Path, "session123") {
		t.Errorf("path should contain session ID: %s", u.Path)
	}
}

func TestXHTTPFillStreamRequestHeadersNoGRPC(t *testing.T) {
	h := http.Header{}
	u, _ := url.Parse("https://example.com/path")
	c := &xhttpConfig{NoGRPCHeader: true}
	err := c.fillStreamRequestHeaders(h, u, "", true)
	if err != nil {
		t.Fatalf("fillStreamRequestHeaders: %v", err)
	}
	if h.Get("Content-Type") != "" {
		t.Errorf("Content-Type = %q, want empty", h.Get("Content-Type"))
	}
}

func TestXHTTPFillStreamRequestHeadersNoBody(t *testing.T) {
	h := http.Header{}
	u, _ := url.Parse("https://example.com/path")
	c := &xhttpConfig{}
	err := c.fillStreamRequestHeaders(h, u, "session123", false)
	if err != nil {
		t.Fatalf("fillStreamRequestHeaders: %v", err)
	}
	if h.Get("Content-Type") != "" {
		t.Errorf("Content-Type = %q, want empty for bodyless request", h.Get("Content-Type"))
	}
	if !strings.Contains(u.Path, "session123") {
		t.Errorf("path should contain session ID: %s", u.Path)
	}
}

func TestXHTTPTransportSelection(t *testing.T) {
	dialRaw := func(ctx context.Context) (net.Conn, error) {
		return nil, errors.New("not used")
	}

	cfgNoFP := &xhttpTLSConfig{forceH2C: false, alpn: []string{"h2", "http/1.1"}}
	tr, err := newXhttpTransport(cfgNoFP, cfgNoFP.alpn, 0, dialRaw)
	if err != nil {
		t.Fatalf("newXhttpTransport (h2): %v", err)
	}
	htr, ok := tr.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", tr)
	}
	if htr.Protocols != nil {
		t.Errorf("h2 transport should not force unencrypted HTTP/2, got %v", htr.Protocols)
	}

	cfgFP := &xhttpTLSConfig{forceH2C: true, alpn: []string{"h2", "http/1.1"}}
	tr2, err := newXhttpTransport(cfgFP, cfgFP.alpn, 0, dialRaw)
	if err != nil {
		t.Fatalf("newXhttpTransport (h2c): %v", err)
	}
	htr2, ok := tr2.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", tr2)
	}
	if htr2.Protocols == nil || !htr2.Protocols.UnencryptedHTTP2() || htr2.Protocols.HTTP1() {
		t.Errorf("h2c transport should force unencrypted HTTP/2 without HTTP/1, got %v", htr2.Protocols)
	}

	cfgH1 := &xhttpTLSConfig{forceH2C: true, alpn: []string{"http/1.1"}}
	tr3, err := newXhttpTransport(cfgH1, cfgH1.alpn, 0, dialRaw)
	if err != nil {
		t.Fatalf("newXhttpTransport (h1.1): %v", err)
	}
	htr3, ok := tr3.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", tr3)
	}
	if htr3.ForceAttemptHTTP2 {
		t.Error("http/1.1 transport should not attempt HTTP/2")
	}
}

func TestXHTTPTLSConfigForceH2C(t *testing.T) {
	ctx := context.Background()
	params := tlsParams{
		serverAddress: "example.com:443",
		sni:           "example.com",
		enabled:       true,
		alpn:          []string{"h2", "http/1.1"},
	}
	cfg, err := newXHTTPTLSConfig(ctx, params)
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}
	if cfg.forceH2C {
		t.Error("no fingerprint should not force h2c")
	}
	params.fingerprint = "firefox"
	cfg, err = newXHTTPTLSConfig(ctx, params)
	if err != nil {
		skipIfFeatureMissing(t, err)
		t.Fatalf("tls config (fp): %v", err)
	}
	if !cfg.forceH2C {
		t.Error("fingerprint should force h2c (uTLS conns are not *tls.Conn)")
	}
	params.fingerprint = ""
	params.reality = true
	params.publicKey = "zpbDgfQxvlM2vbx3M1yM4fNC525q_g8yHiTPikDqjhs"
	cfg, err = newXHTTPTLSConfig(ctx, params)
	if err != nil {
		t.Fatalf("tls config (reality): %v", err)
	}
	if !cfg.forceH2C {
		t.Error("reality should force h2c (uTLS conns are not *tls.Conn)")
	}
}

func TestXHTTPFillPacketRequestHeadersBody(t *testing.T) {
	h := http.Header{}
	u, _ := url.Parse("https://example.com/path")
	c := &xhttpConfig{}
	err := c.fillPacketRequestHeaders(h, u, "sess1", "0", []byte("payload"))
	if err != nil {
		t.Fatalf("fillPacketRequestHeaders: %v", err)
	}
	if !strings.Contains(u.Path, "sess1") {
		t.Errorf("path should contain session: %s", u.Path)
	}
	if !strings.Contains(u.Path, "0") {
		t.Errorf("path should contain seq: %s", u.Path)
	}
}

func TestXHTTPFillPacketRequestHeadersHeaderPlacement(t *testing.T) {
	h := http.Header{}
	u, _ := url.Parse("https://example.com/path")
	c := &xhttpConfig{
		UplinkDataPlacement: xhttpPlacementHeader,
		UplinkDataKey:       "X-Data",
	}
	err := c.fillPacketRequestHeaders(h, u, "sess1", "0", []byte("payload"))
	if err != nil {
		t.Fatalf("fillPacketRequestHeaders: %v", err)
	}
	if h.Get("X-Data-0") == "" {
		t.Error("header X-Data-0 should be set")
	}
}

func TestXHTTPApplyMetaToRequestPath(t *testing.T) {
	h := http.Header{}
	u, _ := url.Parse("https://example.com/path/")
	c := &xhttpConfig{}
	c.applyMetaToRequest(h, u, "session123", "42")
	if !strings.HasSuffix(u.Path, "session123/42") {
		t.Errorf("path = %q, should end with session123/42", u.Path)
	}
}

func TestXHTTPApplyMetaToRequestQuery(t *testing.T) {
	h := http.Header{}
	u, _ := url.Parse("https://example.com/path")
	c := &xhttpConfig{
		SessionPlacement: xhttpPlacementQuery,
		SeqPlacement:     xhttpPlacementQuery,
	}
	c.applyMetaToRequest(h, u, "session123", "42")
	if u.Query().Get("x_session") != "session123" {
		t.Errorf("x_session = %q", u.Query().Get("x_session"))
	}
	if u.Query().Get("x_seq") != "42" {
		t.Errorf("x_seq = %q", u.Query().Get("x_seq"))
	}
}

func TestXHTTPApplyMetaToRequestHeader(t *testing.T) {
	h := http.Header{}
	u, _ := url.Parse("https://example.com/path")
	c := &xhttpConfig{
		SessionPlacement: xhttpPlacementHeader,
		SeqPlacement:     xhttpPlacementHeader,
	}
	c.applyMetaToRequest(h, u, "session123", "42")
	if h.Get("X-Session") != "session123" {
		t.Errorf("X-Session = %q", h.Get("X-Session"))
	}
	if h.Get("X-Seq") != "42" {
		t.Errorf("X-Seq = %q", h.Get("X-Seq"))
	}
}

func TestXHTTPApplyMetaToRequestEmptySession(t *testing.T) {
	h := http.Header{}
	u, _ := url.Parse("https://example.com/path")
	c := &xhttpConfig{}
	c.applyMetaToRequest(h, u, "", "")
	if u.Path != "/path" {
		t.Errorf("path should be unchanged: %q", u.Path)
	}
}

func TestXHTTPProxyStringAddr(t *testing.T) {
	p := &xproxyProxy{
		original: "vless://test@host:443",
		proxyIP:  net.IPv4(1, 2, 3, 4),
	}
	if p.String() != "vless://test@host:443" {
		t.Errorf("String = %q", p.String())
	}
	if !p.Addr().Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("Addr = %v", p.Addr())
	}
}

func TestXHTTPProxyDialContextEmptyAddr(t *testing.T) {
	p := &xproxyProxy{}
	_, err := p.DialContext(context.Background(), "tcp", "")
	if !errors.Is(err, ErrMissingTarget) {
		t.Fatalf("expected ErrMissingTarget, got %v", err)
	}
}

func TestXHTTPProxyDialContextAddrNil(t *testing.T) {
	p := &xproxyProxy{}
	_, err := p.DialContextAddr(context.Background(), "tcp", nil)
	if !errors.Is(err, ErrMissingTarget) {
		t.Fatalf("expected ErrMissingTarget, got %v", err)
	}
}

func TestXHTTPProxyDialSocksaddrBadNetwork(t *testing.T) {
	p := &xproxyProxy{}
	_, err := p.dialSocksaddr(context.Background(), "udp", M.ParseSocksaddr("host:443"))
	if err == nil {
		t.Fatal("expected error for udp network")
	}
}

func TestXHTTPNewXHTTPProxyUnsupportedType(t *testing.T) {
	raw := "socks://user:pass@host.example.com:443?type=xhttp"
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = newXHTTPProxy(raw, u, "socks", Config{})
	if err == nil {
		t.Fatal("expected error for socks+xhttp")
	}
}

func TestXHTTPNewXHTTPProxyVMessInvalidBase64(t *testing.T) {
	raw := "vmess://!!!invalidbase64!!!"
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = newXHTTPProxy(raw, u, "vmess", Config{})
	if err == nil {
		t.Fatal("expected error for invalid vmess base64")
	}
}

func TestXHTTPNewXHTTPProxyVMessInvalidJSON(t *testing.T) {
	b64 := base64.RawStdEncoding.EncodeToString([]byte("not json"))
	raw := "vmess://" + b64
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = newXHTTPProxy(raw, u, "vmess", Config{})
	if err == nil {
		t.Fatal("expected error for invalid vmess JSON")
	}
}

func TestXHTTPNewXHTTPProxyVMessMissingHost(t *testing.T) {
	jsonStr := `{"v":"2","add":"","port":"443","id":"uuid","aid":"0","net":"xhttp"}`
	b64 := base64.RawStdEncoding.EncodeToString([]byte(jsonStr))
	raw := "vmess://" + b64
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = newXHTTPProxy(raw, u, "vmess", Config{})
	if err == nil {
		t.Fatal("expected error for missing host in vmess JSON")
	}
}

func TestXHTTPNewXHTTPProxyVMessMissingPort(t *testing.T) {
	jsonStr := `{"v":"2","add":"host.example.com","port":"","id":"uuid","aid":"0","net":"xhttp"}`
	b64 := base64.RawStdEncoding.EncodeToString([]byte(jsonStr))
	raw := "vmess://" + b64
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = newXHTTPProxy(raw, u, "vmess", Config{})
	if err == nil {
		t.Fatal("expected error for missing port in vmess JSON")
	}
}

func TestXHTTPNewXHTTPProxyVMessWithTLS(t *testing.T) {
	jsonStr := `{"v":"2","add":"host.example.com","port":"443","id":"test-uuid","aid":"0","net":"xhttp","path":"/xh","host":"xh.example.com","tls":"tls","sni":"sni.example.com","alpn":"h2","fp":"chrome"}`
	b64 := base64.RawStdEncoding.EncodeToString([]byte(jsonStr))
	raw := "vmess://" + b64
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p, err := newXHTTPProxy(raw, u, "vmess", Config{})
	if err != nil {
		skipIfFeatureMissing(t, err)
		t.Fatalf("newXHTTPProxy: %v", err)
	}
	if p.security != "auto" {
		t.Errorf("security = %q, want auto", p.security)
	}
	if p.server != "host.example.com" {
		t.Errorf("server = %q", p.server)
	}
	if p.port != 443 {
		t.Errorf("port = %d", p.port)
	}
	if p.xcfg.TLSConfig == nil {
		t.Fatal("TLSConfig should not be nil for tls vmess")
	}
}

func TestXHTTPNewXHTTPProxyVMessGlobalPadding(t *testing.T) {
	jsonStr := `{"v":"2","add":"host.example.com","port":"443","id":"test-uuid","aid":"0","net":"xhttp","global_padding":true,"authenticated_length":true}`
	b64 := base64.RawStdEncoding.EncodeToString([]byte(jsonStr))
	raw := "vmess://" + b64
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p, err := newXHTTPProxy(raw, u, "vmess", Config{})
	if err != nil {
		t.Fatalf("newXHTTPProxy: %v", err)
	}
	if !p.globalPad {
		t.Error("globalPad should be true")
	}
	if !p.authLength {
		t.Error("authLength should be true")
	}
}

func TestXHTTPNewXHTTPProxyVLESSWithFlow(t *testing.T) {
	raw := "vless://uuid-here@host.example.com:443?type=xhttp&path=/xh&flow=xtls-rprx-vision"
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p, err := newXHTTPProxy(raw, u, "vless", Config{})
	if err != nil {
		t.Fatalf("newXHTTPProxy: %v", err)
	}
	if p.flow != "xtls-rprx-vision" {
		t.Errorf("flow = %q", p.flow)
	}
}

func TestXHTTPNewXHTTPProxyVLESSIPHost(t *testing.T) {
	raw := "vless://uuid-here@127.0.0.1:443?type=xhttp&path=/xh"
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p, err := newXHTTPProxy(raw, u, "vless", Config{})
	if err != nil {
		t.Fatalf("newXHTTPProxy: %v", err)
	}
	if !p.proxyIP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("proxyIP = %v, want 127.0.0.1", p.proxyIP)
	}
}

func TestXHTTPParseTLSParamsAllowInsecureUnderscore(t *testing.T) {
	params := url.Values{
		"allow_insecure": {"1"},
		"sni":            {"test.example.com"},
	}
	tlsPrm := parseTLSParams(params, "host.example.com:443")
	if !tlsPrm.insecure {
		t.Error("insecure should be true for allow_insecure=1")
	}
}

func TestXHTTPParseTLSParamsNoReality(t *testing.T) {
	params := url.Values{
		"security": {"tls"},
		"sni":      {"test.example.com"},
	}
	tlsPrm := parseTLSParams(params, "host.example.com:443")
	if tlsPrm.reality {
		t.Error("reality should be false for security=tls")
	}
}

func TestXHTTPParseTLSParamsRealityNoPbk(t *testing.T) {
	params := url.Values{
		"security": {"reality"},
		"sni":      {"test.example.com"},
	}
	tlsPrm := parseTLSParams(params, "host.example.com:443")
	if tlsPrm.reality {
		t.Error("reality should be false when pbk is missing")
	}
}

func TestXHTTPParseTLSParamsShortIDAt(t *testing.T) {
	params := url.Values{
		"security": {"reality"},
		"pbk":      {"6ctfPJwrO36DR251pxfkVaME-LbzR0n3dBDUScySldE"},
		"sid":      {"a1b2c3d4@extra"},
		"sni":      {"test.example.com"},
	}
	tlsPrm := parseTLSParams(params, "host.example.com:443")
	if !tlsPrm.reality {
		t.Fatal("reality should be true")
	}
	if tlsPrm.shortID != "a1b2c3d4" {
		t.Errorf("shortID = %q, want a1b2c3d4", tlsPrm.shortID)
	}
}

func TestXHTTPParseTLSParamsFallbackToServerAddress(t *testing.T) {
	params := url.Values{}
	tlsPrm := parseTLSParams(params, "host.example.com:443")
	if tlsPrm.sni != "host.example.com" {
		t.Errorf("SNI = %q, want host.example.com", tlsPrm.sni)
	}
}

func TestXHTTPParseTLSParamsHostFallback(t *testing.T) {
	params := url.Values{
		"host": {"hostparam.example.com"},
	}
	tlsPrm := parseTLSParams(params, "server.example.com:443")
	if tlsPrm.sni != "hostparam.example.com" {
		t.Errorf("SNI = %q, want hostparam.example.com", tlsPrm.sni)
	}
}

func TestXHTTPIsXHTTPTransportEmpty(t *testing.T) {
	u, _ := url.Parse("https://example.com")
	if isXHTTPTransport(u) {
		t.Error("should be false for no type param")
	}
}

func TestXHTTPIsXHTTPTransportCaseInsensitive(t *testing.T) {
	tests := []string{
		"?type=XHTTP",
		"?type=XHttp",
		"?type=SPLITHTTP",
		"?type=SplitHttp",
	}
	for _, q := range tests {
		u, _ := url.Parse("https://example.com" + q)
		if !isXHTTPTransport(u) {
			t.Errorf("isXHTTPTransport(%q) should be true", q)
		}
	}
}

func TestXHTTPFromURLXHTTPDetection(t *testing.T) {
	raw := "vless://uuid@host.example.com:443?type=xhttp&path=/xh&mode=stream-one"
	_, err := FromURL(Config{}, raw)
	if err != nil {
		t.Fatalf("FromURL with xhttp: %v", err)
	}
}

func TestXHTTPFromURLSplithttpDetection(t *testing.T) {
	raw := "vless://uuid@host.example.com:443?type=splithttp&path=/xh&mode=stream-one"
	_, err := FromURL(Config{}, raw)
	if err != nil {
		t.Fatalf("FromURL with splithttp: %v", err)
	}
}

func TestXHTTPFromURLNonXHTTPNotIntercepted(t *testing.T) {
	raw := "vless://uuid@host.example.com:443?type=ws&path=/ws"
	_, err := FromURL(Config{}, raw)
	if err != nil {
		t.Fatalf("FromURL with ws: %v", err)
	}
}

// Mock types for testing

type mockRoundTripper struct {
	closedIdle bool
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

func (m *mockRoundTripper) CloseIdleConnections() {
	m.closedIdle = true
}

type mockCloserRoundTripper struct {
	mockRoundTripper
	closed bool
}

func (m *mockCloserRoundTripper) Close() error {
	m.closed = true
	return nil
}

// Ensure interfaces are satisfied
var _ http.RoundTripper = (*mockRoundTripper)(nil)
var _ io.Closer = (*mockCloserRoundTripper)(nil)

// Import guard for context
var _ = context.Background
var _ = sync.Mutex{}
