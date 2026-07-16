package singproxy

import (
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseSSH_Basic(t *testing.T) {
	u, _ := url.Parse("ssh://sshuser:sshpass@ssh.example.com:22")
	out := &option.SSHOutboundOptions{}
	if err := parseSSH(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "ssh.example.com" || out.ServerPort != 22 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.User != "sshuser" {
		t.Errorf("user: got %q", out.User)
	}
	if out.Password != "sshpass" {
		t.Errorf("password: got %q", out.Password)
	}
}

func TestParseSSH_DefaultPort(t *testing.T) {
	u, _ := url.Parse("ssh://sshuser@ssh.example.com")
	out := &option.SSHOutboundOptions{}
	if err := parseSSH(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.ServerPort != 22 {
		t.Errorf("default port: got %d, want 22", out.ServerPort)
	}
}

func TestParseSSH_NoPassword(t *testing.T) {
	u, _ := url.Parse("ssh://sshuser@ssh.example.com:2222")
	out := &option.SSHOutboundOptions{}
	if err := parseSSH(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Password != "" {
		t.Errorf("password: got %q, want empty", out.Password)
	}
}

func TestParseShadowTLS_Basic(t *testing.T) {
	u, _ := url.Parse("shadowtls://stlspass@stls.example.com:443?version=3&security=tls&sni=stls-sni.com")
	out := &option.ShadowTLSOutboundOptions{}
	if err := parseShadowTLS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "stls.example.com" || out.ServerPort != 443 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.Password != "stlspass" {
		t.Errorf("password: got %q", out.Password)
	}
	if out.Version != 3 {
		t.Errorf("version: got %d, want 3", out.Version)
	}
	if out.TLS == nil || !out.TLS.Enabled {
		t.Fatal("expected enabled TLS")
	}
	if out.TLS.ServerName != "stls-sni.com" {
		t.Errorf("TLS SNI: got %q", out.TLS.ServerName)
	}
}

func TestParseShadowTLS_DefaultVersion(t *testing.T) {
	u, _ := url.Parse("shadowtls://pass@stls.example.com:443?security=tls&sni=sni.com")
	out := &option.ShadowTLSOutboundOptions{}
	if err := parseShadowTLS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Version != 2 {
		t.Errorf("default version: got %d, want 2", out.Version)
	}
}

func TestParseShadowTLS_InvalidPort(t *testing.T) {
	u, _ := url.Parse("shadowtls://pass@host:abc")
	if u == nil || u.Host == "" {
		return
	}
	out := &option.ShadowTLSOutboundOptions{}
	err := parseShadowTLS(out, u)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestParseAnyTLS_Basic(t *testing.T) {
	u, _ := url.Parse("anytls://anytlspass@anytls.example.com:443?security=tls&sni=anytls-sni.com&insecure=1")
	out := &option.AnyTLSOutboundOptions{}
	if err := parseAnyTLS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "anytls.example.com" || out.ServerPort != 443 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.Password != "anytlspass" {
		t.Errorf("password: got %q", out.Password)
	}
	if out.TLS == nil || !out.TLS.Enabled {
		t.Fatal("expected enabled TLS")
	}
	if out.TLS.ServerName != "anytls-sni.com" {
		t.Errorf("TLS SNI: got %q", out.TLS.ServerName)
	}
	if !out.TLS.Insecure {
		t.Errorf("expected insecure=true")
	}
}

func TestParseAnyTLS_ATLSScheme(t *testing.T) {
	u, _ := url.Parse("atls://pass@anytls-atls.example.com:443?security=tls&sni=sni.com")
	out := &option.AnyTLSOutboundOptions{}
	if err := parseAnyTLS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "anytls-atls.example.com" {
		t.Errorf("server: got %q", out.Server)
	}
}

func TestParseAnyTLS_InvalidPort(t *testing.T) {
	u, _ := url.Parse("anytls://pass@host:abc")
	if u == nil || u.Host == "" {
		return
	}
	out := &option.AnyTLSOutboundOptions{}
	err := parseAnyTLS(out, u)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}
