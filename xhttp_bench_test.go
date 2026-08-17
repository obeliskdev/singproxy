package singproxy

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func BenchmarkNormalizedConfigValues(b *testing.B) {
	c := &xhttpConfig{
		Path:               "x",
		ScMaxEachPostBytes: "100-200",
		SessionPlacement:   "query",
		XPaddingBytes:      "100-1000",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetNormalizedScMaxEachPostBytes()
		_ = c.GetNormalizedSessionKey()
		_ = c.GetNormalizedUplinkDataPlacement()
		_ = c.NormalizedPath()
	}
}

func BenchmarkApplyMasqueradedHeaders(b *testing.B) {
	c := &xhttpConfig{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := make(http.Header, 8)
		c.applyMasqueradedHeaders(h, "fetch")
	}
}

func BenchmarkFillStreamRequestHeaders(b *testing.B) {
	c := &xhttpConfig{Host: "example.com", Path: "x"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := make(http.Header, 8)
		reqURL := &url.URL{Scheme: "https", Host: "example.com", Path: "/x/"}
		if err := c.fillStreamRequestHeaders(h, reqURL, "session-1", true); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWaitReadCloserReadReady(b *testing.B) {
	w := newXhttpWaitReadCloser()
	w.Set(io.NopCloser(strings.NewReader("")))
	var buf [1]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = w.Read(buf[:])
	}
}

func BenchmarkPacketUpWrite(b *testing.B) {
	w := &xhttpPacketUpWriter{
		ctx:                context.Background(),
		cfg:                &xhttpConfig{Host: "example.com", Path: "x"},
		scMaxEachPostBytes: 64 * 1024,
		scMinPostsIntervalMs: xhttpRange{
			Min: 30,
			Max: 30,
		},
		sessionID:  "session-1",
		transport:  staticRoundTripper{},
		reqURL:     "https://example.com/x/",
		method:     "POST",
		discardBuf: make([]byte, 8*1024),
	}
	data := make([]byte, 64*1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.write(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPacketUpWriterWriteBuffered(b *testing.B) {
	w := &xhttpPacketUpWriter{
		ctx:                  context.Background(),
		cfg:                  &xhttpConfig{Host: "example.com", Path: "x"},
		scMaxEachPostBytes:   1 << 30,
		scMinPostsIntervalMs: xhttpRange{Min: 0, Max: 0},
		transport:            staticRoundTripper{},
		buf:                  make([]byte, 0, 1<<20),
	}
	w.writeCond = sync.Cond{L: &w.writeMu}
	data := make([]byte, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Write(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRandStringFromCharset(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = xhttpRandStringFromCharset(200, xhttpCharsetBase62)
	}
}

type staticRoundTripper struct{}

func (staticRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}
