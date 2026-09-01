package singproxy

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// --- naive parser ---

// The naive outbound requires the with_naive_outbound build tag; the
// parser itself is always available, so without the tag the failure
// must come from outbound creation, never from parsing.
func TestParseNaiveParserReachable(t *testing.T) {
	_, err := FromURL(Config{}, "naive+https://user:pass@example.com:443")
	if err == nil {
		return // build includes naive
	}
	const stub = "naive outbound is not included in this build"
	if !strings.Contains(err.Error(), stub) {
		t.Fatalf("expected outbound-creation error, got: %v", err)
	}
}

func TestParseNaiveNoCredsRejected(t *testing.T) {
	u := mustParseURLForTest("naive+https://example.com:443")
	out := newNaiveOptionsForTest()
	if err := parseNaive(out, u); err == nil {
		t.Error("expected error for naive without credentials")
	}
}

func TestParseNaiveSecurityNoneDisablesTLS(t *testing.T) {
	u := mustParseURLForTest("naive+https://user:pass@example.com:443?security=none")
	out := newNaiveOptionsForTest()
	if err := parseNaive(out, u); err != nil {
		t.Fatal(err)
	}
	if out.TLS != nil {
		t.Error("security=none must disable TLS")
	}
}

func mustParseURLForTest(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func newNaiveOptionsForTest() *option.NaiveOutboundOptions {
	return &option.NaiveOutboundOptions{}
}

// --- browser masquerade variants ---

func TestApplyMasqueradedHeadersAllBrowsers(t *testing.T) {
	for _, ua := range []string{"chrome", "firefox", "safari", "edge", "curl", "golang"} {
		c := &xhttpConfig{}
		h := http.Header{}
		h.Set("User-Agent", ua)
		c.applyMasqueradedHeaders(h, "fetch")
		switch ua {
		case "golang":
			if h.Get("User-Agent") != "" {
				t.Errorf("golang variant must strip User-Agent, got %q", h.Get("User-Agent"))
			}
		case "curl":
			if h.Get("User-Agent") == "" {
				t.Error("curl variant must set a UA")
			}
		default:
			if h.Get("User-Agent") == "" {
				t.Errorf("%s variant must set a UA", ua)
			}
			if h.Get("Sec-Fetch-Mode") == "" {
				t.Errorf("%s fetch variant missing Sec-Fetch-Mode", ua)
			}
		}
	}
}

func TestApplyMasqueradedHeadersVariants(t *testing.T) {
	for _, variant := range []string{"nav", "ws", "fetch"} {
		c := &xhttpConfig{}
		h := http.Header{}
		c.applyMasqueradedHeaders(h, variant)
		if variant == "nav" && h.Get("Sec-Fetch-Mode") != "navigate" {
			t.Errorf("nav variant Sec-Fetch-Mode = %q", h.Get("Sec-Fetch-Mode"))
		}
		if variant == "ws" && h.Get("Sec-Fetch-Mode") != "websocket" {
			t.Errorf("ws variant Sec-Fetch-Mode = %q", h.Get("Sec-Fetch-Mode"))
		}
	}
}

// --- reuse manager ---

func TestReuseManagerPickAndClose(t *testing.T) {
	made := 0
	m := &xhttpReuseManager{
		maxConnections: 2,
		maker: func() http.RoundTripper {
			made++
			return &staticResponseTripper{status: http.StatusOK}
		},
	}
	rt1 := m.GetTransport()
	rt2 := m.GetTransport()
	rt3 := m.GetTransport()
	if rt1 == nil || rt2 == nil || rt3 == nil {
		t.Fatal("GetTransport must not return nil")
	}
	closer1, ok := rt1.(interface{ Close() error })
	if !ok {
		t.Fatal("GetTransport result must implement Close")
	}
	closer2, _ := rt2.(interface{ Close() error })
	closer3, _ := rt3.(interface{ Close() error })
	_ = closer1.Close()
	_ = closer2.Close()
	_ = closer3.Close()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	// Double close must be safe.
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestXHTTPReuseTransportRoundTrip(t *testing.T) {
	tr := &staticResponseTripper{status: http.StatusOK}
	entry := &xhttpReuseEntry{}
	entry.leftRequests.Store(10)
	rt := &xhttpReuseTransport{entry: entry}
	entry.transport = tr
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
	_ = rt.Close()
	_ = rt.Close() // double close safe
}

// --- greased CH order ---

func TestXHTTPGetGreasedChOrder(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4} {
		for seed := 0; seed < 4; seed++ {
			order := xhttpGetGreasedChOrder(n, seed)
			if len(order) != n {
				t.Errorf("n=%d seed=%d: got %d entries, want %d", n, seed, len(order), n)
			}
			seen := make(map[int]bool, n)
			for _, v := range order {
				if v < 0 || v >= n {
					t.Errorf("n=%d seed=%d: out of range %d", n, seed, v)
				}
				if seen[v] {
					t.Errorf("n=%d seed=%d: duplicate %d", n, seed, v)
				}
				seen[v] = true
			}
		}
	}
}

// --- direct proxy ---

func TestDirectProxyInterface(t *testing.T) {
	if Direct.String() != "direct" {
		t.Errorf("String() = %q", Direct.String())
	}
	if err := Direct.Close(); err != nil {
		t.Errorf("Close() = %v", err)
	}
}
