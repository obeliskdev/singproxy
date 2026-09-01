package singproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// staticResponseTripper answers every request with the given status and body.
type staticResponseTripper struct {
	status int
	body   string
	calls  atomic.Int32
}

func (s *staticResponseTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	s.calls.Add(1)
	return &http.Response{
		StatusCode: s.status,
		Status:     http.StatusText(s.status),
		Body:       io.NopCloser(newStaticBody(s.body)),
		Request:    r,
	}, nil
}

type staticBody struct {
	data []byte
	pos  int
}

func newStaticBody(s string) *staticBody { return &staticBody{data: []byte(s)} }

func (b *staticBody) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

// failingTripper always fails with the given error.
type failingTripper struct {
	err error
}

func (f *failingTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, f.err
}

func newPacketUpWriterForTest(tr http.RoundTripper, maxBytes int) *xhttpPacketUpWriter {
	w := &xhttpPacketUpWriter{
		ctx:                  context.Background(),
		cancel:               func() {},
		cfg:                  &xhttpConfig{Host: "example.com", Path: "x"},
		scMaxEachPostBytes:   maxBytes,
		scMinPostsIntervalMs: xhttpRange{Min: 0, Max: 0},
		sessionID:            "sess-1",
		transport:            tr,
		reqURL:               "https://example.com/x/",
		method:               "POST",
		discardBuf:           make([]byte, 8*1024),
	}
	w.writeCond = sync.Cond{L: &w.writeMu}
	return w
}

// --- awaitDownload ---

func TestAwaitDownloadSuccess(t *testing.T) {
	c := &xhttpClient{}
	cfg := &xhttpConfig{Host: "example.com", Path: "x"}
	tr := &staticResponseTripper{status: http.StatusOK, body: "payload"}

	wrc, done := c.awaitDownload(context.Background(), tr, cfg, "sess-1", "test")
	if err := <-done; err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	buf := make([]byte, 32)
	n, err := wrc.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "payload" {
		t.Errorf("read %q, want %q", buf[:n], "payload")
	}
	_ = wrc.Close()
}

func TestAwaitDownloadNetworkError(t *testing.T) {
	c := &xhttpClient{}
	cfg := &xhttpConfig{Host: "example.com", Path: "x"}
	tr := &failingTripper{err: errors.New("boom")}

	wrc, done := c.awaitDownload(context.Background(), tr, cfg, "sess-1", "test")
	if err := <-done; err == nil {
		t.Fatal("expected error")
	}
	if wrc.Err() == nil {
		t.Error("wrc.Err() should carry the error")
	}
}

func TestAwaitDownloadBadStatus(t *testing.T) {
	c := &xhttpClient{}
	cfg := &xhttpConfig{Host: "example.com", Path: "x"}
	tr := &staticResponseTripper{status: http.StatusForbidden}

	wrc, done := c.awaitDownload(context.Background(), tr, cfg, "sess-1", "test")
	err := <-done
	if err == nil {
		t.Fatal("expected error for bad status")
	}
	if got := wrc.Err(); got == nil {
		t.Error("wrc.Err() should carry the bad-status error")
	}
}

// --- xhttpPacketUpWriter ---

func TestPacketUpWriterWriteFullChunks(t *testing.T) {
	tr := &staticResponseTripper{status: http.StatusOK}
	w := newPacketUpWriterForTest(tr, 16)

	data := make([]byte, 16)
	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(data) {
		t.Errorf("wrote %d, want %d", n, len(data))
	}
	if tr.calls.Load() != 1 {
		t.Errorf("expected 1 POST, got %d", tr.calls.Load())
	}
	_ = w.Close()
}

func TestPacketUpWriterWriteFlushOnClose(t *testing.T) {
	tr := &staticResponseTripper{status: http.StatusOK}
	w := newPacketUpWriterForTest(tr, 1<<30)

	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if tr.calls.Load() != 0 {
		t.Fatalf("no flush expected before close, got %d calls", tr.calls.Load())
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if tr.calls.Load() != 1 {
		t.Errorf("close should flush exactly once, got %d calls", tr.calls.Load())
	}
}

func TestPacketUpWriterWriteAfterCloseFails(t *testing.T) {
	tr := &staticResponseTripper{status: http.StatusOK}
	w := newPacketUpWriterForTest(tr, 1<<30)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Error("write after close must fail")
	}
}

func TestPacketUpWriterBadStatusStopsWrites(t *testing.T) {
	tr := &staticResponseTripper{status: http.StatusInternalServerError}
	w := newPacketUpWriterForTest(tr, 16)
	if _, err := w.Write(make([]byte, 16)); err == nil {
		t.Error("write must fail on 5xx status")
	}
	_ = w.Close()
}

// --- xhttpConn ---

func TestXHTTPConnErrAfterError(t *testing.T) {
	wrc := newXhttpWaitReadCloser()
	wrc.CloseWithError(errors.New("boom"))
	if got := wrc.Err(); got == nil || got.Error() != "boom" {
		t.Errorf("Err(): got %v, want boom", got)
	}
}

func TestXHTTPConnDeadlineCancel(t *testing.T) {
	pr, pw := net.Pipe()
	defer pr.Close()
	conn := &xhttpConn{writer: pw, reader: pr}
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(buf)
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("read did not unblock after deadline")
	}
	_ = conn.Close()
}

// TestXHTTPConnSeparateDeadlines verifies SetReadDeadline and
// SetWriteDeadline no longer share one timer: setting both must keep
// both alive, and clearing the read deadline must not clear the write
// deadline.
func TestXHTTPConnSeparateDeadlines(t *testing.T) {
	pr, pw := net.Pipe()
	defer pr.Close()
	conn := &xhttpConn{writer: pw, reader: pr}

	if err := conn.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = conn.Write([]byte("x"))
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("write did not unblock after write deadline")
	}
	_ = conn.Close()
}

// --- EffectiveMode ---

func TestEffectiveMode(t *testing.T) {
	cases := []struct {
		mode      string
		reality   bool
		download  bool
		effective string
	}{
		{"", false, false, "packet-up"},
		{"", true, false, "stream-one"},
		{"", true, true, "stream-up"},
		{"auto", false, false, "packet-up"},
		{"stream-one", false, false, "stream-one"},
		{"stream-up", false, false, "stream-up"},
		{"packet-up", false, false, "packet-up"},
		{"auto", true, false, "stream-one"},
	}
	for _, c := range cases {
		cfg := &xhttpConfig{Mode: c.mode}
		if c.download {
			cfg.DownloadConfig = &xhttpConfig{}
		}
		got := cfg.EffectiveMode(c.reality)
		if got != c.effective {
			t.Errorf("EffectiveMode(%q, reality=%v, download=%v) = %q, want %q",
				c.mode, c.reality, c.download, got, c.effective)
		}
	}
}

// --- dialXHTTP error propagation ---

func TestDialXHTTPBadModeRejected(t *testing.T) {
	xcfg, err := parseXHTTPTransportParams(nil, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	xcfg.Mode = "not-a-mode"
	_, err = dialXHTTP(context.Background(), xcfg, "example.com", 443, Config{})
	if err == nil {
		t.Fatal("expected error for unsupported mode")
	}
	if !errors.Is(err, err) {
		t.Error("sanity")
	}
}

var _ http.RoundTripper = (*staticResponseTripper)(nil)
var _ http.RoundTripper = (*failingTripper)(nil)
