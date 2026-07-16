package singproxy

import (
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseHTTP_Basic(t *testing.T) {
	u, _ := url.Parse("http://user:pass@http-proxy.example.com:8080")
	out := &option.HTTPOutboundOptions{}
	if err := parseHTTP(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "http-proxy.example.com" || out.ServerPort != 8080 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.Username != "user" || out.Password != "pass" {
		t.Errorf("auth: got %q/%q", out.Username, out.Password)
	}
}

func TestParseHTTP_NoAuth(t *testing.T) {
	u, _ := url.Parse("http://noauth.example.com:8080")
	out := &option.HTTPOutboundOptions{}
	if err := parseHTTP(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Username != "" || out.Password != "" {
		t.Errorf("auth: got %q/%q, want empty", out.Username, out.Password)
	}
}

func TestParseHTTP_HTTPS_AutoTLS(t *testing.T) {
	u, _ := url.Parse("https://https.example.com:443")
	out := &option.HTTPOutboundOptions{}
	if err := parseHTTP(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TLS == nil || !out.TLS.Enabled {
		t.Fatal("expected auto-enabled TLS for https scheme")
	}
	if out.TLS.ServerName != "https.example.com" {
		t.Errorf("TLS SNI: got %q", out.TLS.ServerName)
	}
}

func TestParseHTTP_HTTP2_AutoTLSAndALPN(t *testing.T) {
	u, _ := url.Parse("http2://h2.example.com:443")
	out := &option.HTTPOutboundOptions{}
	if err := parseHTTP(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TLS == nil || !out.TLS.Enabled {
		t.Fatal("expected auto-enabled TLS for http2 scheme")
	}
	found := false
	for _, a := range out.TLS.ALPN {
		if a == "h2" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected h2 in ALPN, got %v", out.TLS.ALPN)
	}
}

func TestParseHTTP_EmptyHost(t *testing.T) {
	u, _ := url.Parse("http://:8080")
	out := &option.HTTPOutboundOptions{}
	err := parseHTTP(out, u)
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestParseHTTP_InvalidPort(t *testing.T) {
	u, _ := url.Parse("http://host:abc")
	out := &option.HTTPOutboundOptions{}
	if u == nil || u.Hostname() == "" {
		return
	}
	err := parseHTTP(out, u)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestParseHTTP_TLSWithParams(t *testing.T) {
	u, _ := url.Parse("http://host:8080?security=tls&sni=custom-sni.com&insecure=1")
	out := &option.HTTPOutboundOptions{}
	if err := parseHTTP(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TLS == nil || !out.TLS.Enabled {
		t.Fatal("expected enabled TLS from security=tls")
	}
	if out.TLS.ServerName != "custom-sni.com" {
		t.Errorf("TLS SNI: got %q", out.TLS.ServerName)
	}
	if !out.TLS.Insecure {
		t.Errorf("expected insecure=true")
	}
}
