package singproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestFromURL_Empty(t *testing.T) {
	_, err := FromURL(8*time.Second, "")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestFromURL_Direct(t *testing.T) {
	p, err := FromURL(8*time.Second, "direct")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.String() != "direct" {
		t.Errorf("String(): got %q, want direct", p.String())
	}
}

func TestFromURL_SchemelessWithHostPort(t *testing.T) {
	p, err := FromURL(8*time.Second, "user:pass@host:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := p.(*SingBoxProxy).options.(*option.HTTPOutboundOptions)
	if opts.Server != "host" || opts.ServerPort != 8080 {
		t.Errorf("server/port: got %s:%d", opts.Server, opts.ServerPort)
	}
	if opts.Username != "user" || opts.Password != "pass" {
		t.Errorf("auth: got %q/%q", opts.Username, opts.Password)
	}
}

func TestFromURL_SchemelessNoColon(t *testing.T) {
	_, err := FromURL(8*time.Second, "just-a-host")
	if err == nil {
		t.Fatal("expected error for schemeless without colon")
	}
}

func TestFromURL_InvalidURL(t *testing.T) {
	_, err := FromURL(8*time.Second, "://no-scheme")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestFromURL_Tor(t *testing.T) {
	p, err := FromURL(8*time.Second, "tor://")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy for tor")
	}
}

func TestFromURL_DirectString(t *testing.T) {
	p, err := FromURL(8*time.Second, "direct")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != Direct {
		t.Errorf("expected Direct proxy, got %v", p)
	}
}

func TestSingBoxProxy_String(t *testing.T) {
	original := "vless://uuid@host:443?encryption=none"
	p := &SingBoxProxy{original: original}
	if p.String() != original {
		t.Errorf("String(): got %q, want %q", p.String(), original)
	}
}

func TestSingBoxProxy_Addr_NilByDefault(t *testing.T) {
	p := &SingBoxProxy{}
	if p.Addr() != nil {
		t.Errorf("Addr(): got %v, want nil", p.Addr())
	}
}

func TestDialContext_EmptyAddr(t *testing.T) {
	p := &SingBoxProxy{timeout: time.Second}
	_, err := p.DialContext(context.Background(), "tcp", "")
	if err != ErrMissingTarget {
		t.Errorf("expected ErrMissingTarget, got %v", err)
	}
}

func TestDialContextAddr_NilAddr(t *testing.T) {
	p := &SingBoxProxy{timeout: time.Second}
	_, err := p.DialContextAddr(context.Background(), "tcp", nil)
	if err != ErrMissingTarget {
		t.Errorf("expected ErrMissingTarget, got %v", err)
	}
}

func TestDialContext_InvalidNetwork(t *testing.T) {
	p := &SingBoxProxy{timeout: time.Second}
	_, err := p.DialContext(context.Background(), "invalid", "host:443")
	if err == nil {
		t.Fatal("expected error for invalid network")
	}
}

func TestDialContextAddr_InvalidNetwork(t *testing.T) {
	p := &SingBoxProxy{timeout: time.Second}
	addr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443}
	_, err := p.DialContextAddr(context.Background(), "invalid", addr)
	if err == nil {
		t.Fatal("expected error for invalid network")
	}
}

func TestFromURLs_Mixed(t *testing.T) {
	proxies, errs := FromURLs(8*time.Second, "direct", "invalid-scheme://whatever")
	if len(proxies) != 1 {
		t.Errorf("expected 1 proxy, got %d", len(proxies))
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
}

func TestFromURLs_AllValid(t *testing.T) {
	proxies, errs := FromURLs(8*time.Second, "direct", "direct")
	if len(proxies) != 2 {
		t.Errorf("expected 2 proxies, got %d", len(proxies))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d", len(errs))
	}
}

func TestFromURLs_AllInvalid(t *testing.T) {
	proxies, errs := FromURLs(8*time.Second, "bad1://x", "bad2://y")
	if len(proxies) != 0 {
		t.Errorf("expected 0 proxies, got %d", len(proxies))
	}
	if len(errs) != 2 {
		t.Errorf("expected 2 errors, got %d", len(errs))
	}
}

func TestFromURLs_Empty(t *testing.T) {
	proxies, errs := FromURLs(8 * time.Second)
	if len(proxies) != 0 || len(errs) != 0 {
		t.Errorf("expected empty results, got %d proxies, %d errors", len(proxies), len(errs))
	}
}
