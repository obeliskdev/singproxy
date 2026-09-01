package singproxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestXHTTPStreamOneConnectFailureReturns guards against the former
// infinite hang: when the remote server refuses the connection, the
// dial must return an error instead of blocking forever on a channel
// that was never written in the error path.
func TestXHTTPStreamOneConnectFailureReturns(t *testing.T) {
	p, err := FromURL(Config{DialTimeout: 2 * time.Second},
		"vless://12345678-1234-1234-1234-123456789abc@127.0.0.1:1?type=xhttp&mode=stream-one")
	if err != nil {
		t.Skipf("parse failed: %v", err)
	}
	defer p.Close()

	assertDialReturns(t, p)
}

// TestXHTTPStreamUpConnectFailureReturns guards against the former
// zero-read hang in awaitDownload when the download request failed.
func TestXHTTPStreamUpConnectFailureReturns(t *testing.T) {
	p, err := FromURL(Config{DialTimeout: 2 * time.Second},
		"vless://12345678-1234-1234-1234-123456789abc@127.0.0.1:1?type=xhttp&mode=stream-up")
	if err != nil {
		t.Skipf("parse failed: %v", err)
	}
	defer p.Close()

	assertDialReturns(t, p)
}

// TestXHTTPPacketUpConnectFailureReturns guards against the former
// zero-read hang in awaitDownload for packet-up mode.
func TestXHTTPPacketUpConnectFailureReturns(t *testing.T) {
	p, err := FromURL(Config{DialTimeout: 2 * time.Second},
		"vless://12345678-1234-1234-1234-123456789abc@127.0.0.1:1?type=xhttp&mode=packet-up")
	if err != nil {
		t.Skipf("parse failed: %v", err)
	}
	defer p.Close()

	assertDialReturns(t, p)
}

// TestXHTTPStreamOneBadStatusReturns guards against two former hangs:
// the error path never signalling the caller, and the request body
// pipe blocking the transport write loop against servers that drain
// the request body before responding (HTTP/1.1 semantics).
func TestXHTTPStreamOneBadStatusReturns(t *testing.T) {
	// A server that answers every request with 404 before reading the
	// request body, like an HTTP/2 or misconfigured real server would.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	link := "vless://12345678-1234-1234-1234-123456789abc@" + srv.Listener.Addr().String() +
		"?type=xhttp&mode=stream-one&security=none"
	p, err := FromURL(Config{DialTimeout: 2 * time.Second}, link)
	if err != nil {
		t.Skipf("parse failed: %v", err)
	}
	defer p.Close()

	start := time.Now()
	assertDialReturns(t, p)
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Errorf("dial took %v, expected fast failure near DialTimeout", elapsed)
	}
}

func assertDialReturns(t *testing.T, p Proxy) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.DialContext(t.Context(), "tcp", "127.0.0.1:80")
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("dial did not return within 10s")
	}
}

// TestFromURLsPreservesOrder verifies that FromURLs keeps the input
// order of successful proxies.
func TestFromURLsPreservesOrder(t *testing.T) {
	urls := []string{
		"socks://u:p@10.1.1.1:1080",
		"not-a-proxy",
		"socks://u:p@10.2.2.2:1080",
		"socks://u:p@10.3.3.3:1080",
	}
	proxies, errs := FromURLs(Config{DialTimeout: 5 * time.Second}, urls...)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
	if !containsURL(errs[0], "#1") {
		t.Errorf("error should reference original index 1, got: %v", errs[0])
	}
	if len(proxies) != 3 {
		t.Fatalf("expected 3 proxies, got %d", len(proxies))
	}
	want := []string{"10.1.1.1", "10.2.2.2", "10.3.3.3"}
	for i, w := range want {
		if got := proxies[i].Addr(); !got.Equal(net.ParseIP(w)) {
			t.Errorf("proxies[%d].Addr(): got %v, want %s", i, got, w)
		}
	}
}

func containsURL(err error, marker string) bool {
	return err != nil && strings.Contains(err.Error(), marker)
}

// TestVMessXHTTPJSONRoutesToXHTTP verifies that vmess links whose JSON
// net field is xhttp or splithttp are handled by the XHTTP client
// instead of being rejected as an unsupported vmess network.
func TestVMessXHTTPJSONRoutesToXHTTP(t *testing.T) {
	const b64 = "eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OWFiYyIsIm5ldCI6InNwbGl0aHR0cCIsImhvc3QiOiJleGFtcGxlLmNvbSIsInBhdGgiOiIveCIsInRscyI6InRscyJ9"
	p, err := FromURL(Config{}, "vmess://"+b64)
	if err != nil {
		t.Fatalf("vmess splithttp JSON should parse: %v", err)
	}
	defer p.Close()
	if _, ok := p.(*xproxyProxy); !ok {
		t.Fatalf("expected *xproxyProxy for vmess+splithttp, got %T", p)
	}
}

// TestVLESSXHTTPQueryParamsRejectedForSS ensures ss links never claim
// xhttp transport support.
func TestVLESSXHTTPQueryParamsRejectedForSS(t *testing.T) {
	_, err := FromURL(Config{}, "ss://YWJjZGVmZ2hpamtsbW5vcA@example.com:8080?type=xhttp")
	if err == nil {
		t.Fatal("expected error for ss with xhttp transport")
	}
}

// TestURLValuesQueryParamsEmpty checks that a link without any query
// parameters parses without panics.
func TestURLValuesQueryParamsEmpty(t *testing.T) {
	u, err := url.Parse("socks://u:p@example.com:1080")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Query()) != 0 {
		t.Fatal("expected empty query")
	}
}
