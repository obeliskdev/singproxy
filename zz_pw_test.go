package singproxy

import (
	"context"
	"testing"
)

func BenchmarkPacketUpWriteParts(b *testing.B) {
	w := &xhttpPacketUpWriter{
		ctx:                  context.Background(),
		cfg:                  &xhttpConfig{Host: "example.com", Path: "x"},
		scMaxEachPostBytes:   64 * 1024,
		scMinPostsIntervalMs: xhttpRange{Min: 30, Max: 30},
		sessionID:            "session-1",
		transport:            staticRoundTripper{},
		reqURL:               "https://example.com/x/",
		method:               "POST",
		discardBuf:           make([]byte, 8*1024),
	}
	data := make([]byte, 64*1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := w.write(data); err != nil {
			b.Fatal(err)
		}
	}
}
