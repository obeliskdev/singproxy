package singproxy

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseSOCKS_Socks5(t *testing.T) {
	u, _ := url.Parse("socks5://user:pass@socks5.example.com:1080")
	out := &option.SOCKSOutboundOptions{}
	if err := parseSOCKS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "socks5.example.com" || out.ServerPort != 1080 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.Version != "5" {
		t.Errorf("version: got %q, want 5", out.Version)
	}
	if out.Username != "user" || out.Password != "pass" {
		t.Errorf("auth: got %q/%q", out.Username, out.Password)
	}
}

func TestParseSOCKS_Socks4(t *testing.T) {
	u, _ := url.Parse("socks4://socks4.example.com:1080")
	out := &option.SOCKSOutboundOptions{}
	if err := parseSOCKS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Version != "4" {
		t.Errorf("version: got %q, want 4", out.Version)
	}
}

func TestParseSOCKS_Socks4a(t *testing.T) {
	u, _ := url.Parse("socks4a://socks4a.example.com:1080")
	out := &option.SOCKSOutboundOptions{}
	if err := parseSOCKS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Version != "4" {
		t.Errorf("version: got %q, want 4", out.Version)
	}
}

func TestParseSOCKS_Socks5NoAuth(t *testing.T) {
	u, _ := url.Parse("socks5://noauth.example.com:1080")
	out := &option.SOCKSOutboundOptions{}
	if err := parseSOCKS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Username != "" || out.Password != "" {
		t.Errorf("auth: got %q/%q, want empty", out.Username, out.Password)
	}
}

func TestParseSOCKS_LegacyBase64(t *testing.T) {
	encoded := base64.RawStdEncoding.EncodeToString([]byte("user:pass@b64socks.example.com:1080"))
	u, _ := url.Parse("socks://" + encoded)
	out := &option.SOCKSOutboundOptions{}
	if err := parseSOCKS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "b64socks.example.com" || out.ServerPort != 1080 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.Version != "5" {
		t.Errorf("version: got %q, want 5", out.Version)
	}
	if out.Username != "user" || out.Password != "pass" {
		t.Errorf("auth: got %q/%q", out.Username, out.Password)
	}
}

func TestParseSOCKS_EmptyHost(t *testing.T) {
	u, _ := url.Parse("socks5://:1080")
	out := &option.SOCKSOutboundOptions{}
	err := parseSOCKS(out, u)
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestParseSOCKS_InvalidPort(t *testing.T) {
	u, _ := url.Parse("socks5://host:abc")
	if u == nil {
		return
	}
	out := &option.SOCKSOutboundOptions{}
	err := parseSOCKS(out, u)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestParseSOCKS_BareSocksScheme(t *testing.T) {
	u, _ := url.Parse("socks://user:pass@bare.example.com:1080")
	out := &option.SOCKSOutboundOptions{}
	if err := parseSOCKS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Version != "5" {
		t.Errorf("version: got %q, want 5", out.Version)
	}
}
