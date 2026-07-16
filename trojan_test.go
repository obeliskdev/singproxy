package singproxy

import (
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseTrojan_Basic(t *testing.T) {
	u, _ := url.Parse("trojan://pass123@trojan.example.com:443?security=tls&sni=trojan.example.com")
	out := &option.TrojanOutboundOptions{}
	if err := parseTrojan(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "trojan.example.com" || out.ServerPort != 443 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.Password != "pass123" {
		t.Errorf("password: got %q, want pass123", out.Password)
	}
	if out.TLS == nil || !out.TLS.Enabled {
		t.Fatal("expected enabled TLS")
	}
	if out.TLS.ServerName != "trojan.example.com" {
		t.Errorf("TLS SNI: got %q", out.TLS.ServerName)
	}
}

func TestParseTrojan_PasswordInURL(t *testing.T) {
	u, _ := url.Parse("trojan://user:pass@trojan.example.com:443?security=tls")
	out := &option.TrojanOutboundOptions{}
	if err := parseTrojan(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Password != "pass" {
		t.Errorf("password: got %q, want pass (from password part)", out.Password)
	}
}

func TestParseTrojan_WS_Transport(t *testing.T) {
	u, _ := url.Parse("trojan://pass@trojan.example.com:443?security=tls&type=ws&path=/ws&host=ws-host.com")
	out := &option.TrojanOutboundOptions{}
	if err := parseTrojan(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Transport == nil || out.Transport.Type != "ws" {
		t.Fatalf("transport: expected ws, got %+v", out.Transport)
	}
	if out.Transport.WebsocketOptions.Path != "/ws" {
		t.Errorf("path: got %q", out.Transport.WebsocketOptions.Path)
	}
}

func TestParseTrojan_GoAliases(t *testing.T) {
	u, _ := url.Parse("trojan-go://secretpass@tg.example.com:443?ssl_verify=false&ssl_sni=tg-sni.com&type=ws&path=/tg")
	out := &option.TrojanOutboundOptions{}
	if err := parseTrojan(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Password != "secretpass" {
		t.Errorf("password: got %q", out.Password)
	}
	if out.TLS == nil || !out.TLS.Insecure {
		t.Errorf("expected insecure=true from ssl_verify=false")
	}
	if out.TLS.ServerName != "tg-sni.com" {
		t.Errorf("SNI from ssl_sni: got %q, want tg-sni.com", out.TLS.ServerName)
	}
}

func TestParseTrojan_InvalidPort(t *testing.T) {
	u, _ := url.Parse("trojan://pass@host:abc")
	if u == nil {
		return
	}
	out := &option.TrojanOutboundOptions{}
	err := parseTrojan(out, u)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestParseTrojan_NoHostPort(t *testing.T) {
	u, _ := url.Parse("trojan://pass@host")
	if u == nil {
		return
	}
	out := &option.TrojanOutboundOptions{}
	err := parseTrojan(out, u)
	if err == nil {
		t.Fatal("expected error for missing port")
	}
}
