package singproxy

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

var _ option.ServerOptionsWrapper = (*option.VLESSOutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.VMessOutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.TrojanOutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.ShadowsocksOutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.ShadowsocksROutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.TUICOutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.HysteriaOutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.Hysteria2OutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.SSHOutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.SOCKSOutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.HTTPOutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.ShadowTLSOutboundOptions)(nil)
var _ option.ServerOptionsWrapper = (*option.AnyTLSOutboundOptions)(nil)

func TestFromURL_Empty(t *testing.T) {
	_, err := FromURL(Config{DialTimeout: 8 * time.Second}, "")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestFromURL_Direct(t *testing.T) {
	p, err := FromURL(Config{DialTimeout: 8 * time.Second}, "direct")
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
	p, err := FromURL(Config{DialTimeout: 8 * time.Second}, "user:pass@host:8080")
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
	_, err := FromURL(Config{DialTimeout: 8 * time.Second}, "just-a-host")
	if err == nil {
		t.Fatal("expected error for schemeless without colon")
	}
}

func TestFromURL_InvalidURL(t *testing.T) {
	_, err := FromURL(Config{DialTimeout: 8 * time.Second}, "://no-scheme")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestFromURL_Tor(t *testing.T) {
	p, err := FromURL(Config{DialTimeout: 8 * time.Second}, "tor://127.0.0.1:9050")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy for tor")
	}
}

// TestFromURL_TorHostlessRejected guards against the former panic: a
// tor link without a socks host used to parse successfully and then
// segfault on the first dial.
func TestFromURL_TorHostlessRejected(t *testing.T) {
	_, err := FromURL(Config{DialTimeout: 8 * time.Second}, "tor://")
	if err == nil {
		t.Fatal("expected error for hostless tor link")
	}
}

func TestFromURL_DirectString(t *testing.T) {
	p, err := FromURL(Config{DialTimeout: 8 * time.Second}, "direct")
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
	p := &SingBoxProxy{cfg: Config{DialTimeout: time.Second}}
	_, err := p.DialContext(context.Background(), "tcp", "")
	if err != ErrMissingTarget {
		t.Errorf("expected ErrMissingTarget, got %v", err)
	}
}

func TestDialContextAddr_NilAddr(t *testing.T) {
	p := &SingBoxProxy{cfg: Config{DialTimeout: time.Second}}
	_, err := p.DialContextAddr(context.Background(), "tcp", nil)
	if err != ErrMissingTarget {
		t.Errorf("expected ErrMissingTarget, got %v", err)
	}
}

func TestDialContext_InvalidNetwork(t *testing.T) {
	p := &SingBoxProxy{cfg: Config{DialTimeout: time.Second}}
	_, err := p.DialContext(context.Background(), "invalid", "host:443")
	if err == nil {
		t.Fatal("expected error for invalid network")
	}
}

func TestDialContextAddr_InvalidNetwork(t *testing.T) {
	p := &SingBoxProxy{cfg: Config{DialTimeout: time.Second}}
	addr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443}
	_, err := p.DialContextAddr(context.Background(), "invalid", addr)
	if err == nil {
		t.Fatal("expected error for invalid network")
	}
}

func TestFromURLs_Mixed(t *testing.T) {
	proxies, errs := FromURLs(Config{DialTimeout: 8 * time.Second}, "direct", "invalid-scheme://whatever")
	if len(proxies) != 1 {
		t.Errorf("expected 1 proxy, got %d", len(proxies))
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
}

func TestFromURLs_AllValid(t *testing.T) {
	proxies, errs := FromURLs(Config{DialTimeout: 8 * time.Second}, "direct", "direct")
	if len(proxies) != 2 {
		t.Errorf("expected 2 proxies, got %d", len(proxies))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d", len(errs))
	}
}

func TestFromURLs_AllInvalid(t *testing.T) {
	proxies, errs := FromURLs(Config{DialTimeout: 8 * time.Second}, "bad1://x", "bad2://y")
	if len(proxies) != 0 {
		t.Errorf("expected 0 proxies, got %d", len(proxies))
	}
	if len(errs) != 2 {
		t.Errorf("expected 2 errors, got %d", len(errs))
	}
}

func TestFromURLs_Empty(t *testing.T) {
	proxies, errs := FromURLs(Config{DialTimeout: 8 * time.Second})
	if len(proxies) != 0 || len(errs) != 0 {
		t.Errorf("expected empty results, got %d proxies, %d errors", len(proxies), len(errs))
	}
}

func TestResolveHostIP(t *testing.T) {
	cases := []struct {
		host string
		want net.IP
	}{
		{"1.2.3.4", net.ParseIP("1.2.3.4")},
		{"2001:db8::1", net.ParseIP("2001:db8::1")},
		{"", nil},
	}
	for _, tc := range cases {
		if got := resolveHostIP(tc.host); !got.Equal(tc.want) {
			t.Errorf("resolveHostIP(%q): got %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestFromURL_AddrResolvedFromIP(t *testing.T) {
	p, err := FromURL(Config{DialTimeout: 8 * time.Second}, "vless://uuid@1.2.3.4:443?encryption=none")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := p.Addr(); !got.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("Addr(): got %v, want 1.2.3.4", got)
	}
}

func TestFromURL_WireGuard_AddrResolved(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	wgPrivateKey := "gCrpA4g8MvjGn85nslmf8Uv25soA9j+R5f6vOa3a41E="
	wgPublicKey := "w9q0T7aiJ27v39yO85yD5jY3kQ1Oa2u5b8a/cDef3gY="
	u := "wireguard://" + url.PathEscape(wgPrivateKey) + "@1.1.1.1:51820?publickey=" + url.PathEscape(wgPublicKey) + "&address=10.0.0.1/32"
	p, err := FromURL(Config{DialTimeout: 8 * time.Second}, u)
	if err != nil {
		skipIfFeatureMissing(t, err)
		t.Fatalf("unexpected error: %v", err)
	}
	// The proxy address of a WireGuard tunnel is the address the client
	// holds inside the tunnel, not the public peer endpoint.
	if got := p.Addr(); !got.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("Addr(): got %v, want 10.0.0.1", got)
	}
}

func TestWireGuardDomainPeerDoesNotPanic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live DNS test in short mode")
	}
	wgPrivateKey := "gCrpA4g8MvjGn85nslmf8Uv25soA9j+R5f6vOa3a41E="
	wgPublicKey := "w9q0T7aiJ27v39yO85yD5jY3kQ1Oa2u5b8a/cDef3gY="
	u := "wireguard://" + url.PathEscape(wgPrivateKey) + "@example.com:51820?publickey=" + url.PathEscape(wgPublicKey) + "&address=10.0.0.1/32"
	p, err := FromURL(Config{DialTimeout: 5 * time.Second}, u)
	if err != nil {
		skipIfFeatureMissing(t, err)
		t.Fatalf("FromURL failed: %v", err)
	}
	conn, err := p.DialContext(context.Background(), "tcp", "1.1.1.1:443")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("expected a dial error (no real wireguard server), got success")
	}
	t.Logf("dial result: %v", err)
}

func TestWireGuardDomainTargetDoesNotPanic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live DNS test in short mode")
	}
	wgPrivateKey := "gCrpA4g8MvjGn85nslmf8Uv25soA9j+R5f6vOa3a41E="
	wgPublicKey := "w9q0T7aiJ27v39yO85yD5jY3kQ1Oa2u5b8a/cDef3gY="
	u := "wireguard://" + url.PathEscape(wgPrivateKey) + "@1.1.1.1:51820?publickey=" + url.PathEscape(wgPublicKey) + "&address=10.0.0.1/32"
	p, err := FromURL(Config{DialTimeout: 5 * time.Second}, u)
	if err != nil {
		skipIfFeatureMissing(t, err)
		t.Fatalf("FromURL failed: %v", err)
	}
	conn, err := p.DialContext(context.Background(), "tcp", "example.com:443")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("expected a dial error (no real wireguard server), got success")
	}
	t.Logf("dial result: %v", err)
}
