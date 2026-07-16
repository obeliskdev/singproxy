package singproxy

import (
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseTUIC_Basic(t *testing.T) {
	u, _ := url.Parse("tuic://tuic-uuid:tuicpass@tuic.example.com:443?sni=tuic-sni.com&alpn=h3&insecure=1&congestion_control=bbr&udp_relay_mode=native")
	out := &option.TUICOutboundOptions{}
	if err := parseTUIC(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "tuic.example.com" || out.ServerPort != 443 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.UUID != "tuic-uuid" {
		t.Errorf("UUID: got %q", out.UUID)
	}
	if out.Password != "tuicpass" {
		t.Errorf("password: got %q", out.Password)
	}
	if out.CongestionControl != "bbr" {
		t.Errorf("congestion: got %q", out.CongestionControl)
	}
	if out.UDPRelayMode != "native" {
		t.Errorf("udp relay: got %q", out.UDPRelayMode)
	}
	if out.TLS == nil || !out.TLS.Enabled {
		t.Fatal("expected enabled TLS")
	}
	if out.TLS.ServerName != "tuic-sni.com" {
		t.Errorf("TLS SNI: got %q", out.TLS.ServerName)
	}
	if !out.TLS.Insecure {
		t.Errorf("expected insecure=true")
	}
	if len(out.TLS.ALPN) != 1 || out.TLS.ALPN[0] != "h3" {
		t.Errorf("ALPN: got %v", out.TLS.ALPN)
	}
}

func TestParseTUIC_SNI_FallbackToHost(t *testing.T) {
	u, _ := url.Parse("tuic://uuid:pass@tuic.example.com:443")
	out := &option.TUICOutboundOptions{}
	if err := parseTUIC(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TLS.ServerName != "tuic.example.com" {
		t.Errorf("SNI fallback: got %q, want tuic.example.com", out.TLS.ServerName)
	}
}

func TestParseTUIC_AllowInsecureUnderscore(t *testing.T) {
	u, _ := url.Parse("tuic://uuid:pass@tuic.example.com:443?allow_insecure=1")
	out := &option.TUICOutboundOptions{}
	if err := parseTUIC(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.TLS.Insecure {
		t.Errorf("expected insecure=true from allow_insecure=1")
	}
}

func TestParseTUIC_DisableSNI(t *testing.T) {
	u, _ := url.Parse("tuic://uuid:pass@tuic.example.com:443?disable_sni=1")
	out := &option.TUICOutboundOptions{}
	if err := parseTUIC(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.TLS.DisableSNI {
		t.Errorf("expected DisableSNI=true")
	}
}

func TestParseHysteria_Basic(t *testing.T) {
	u, _ := url.Parse("hy://authstring@hy.example.com:443?upmbps=100&downmbps=200&peer=peer-sni.com&insecure=1&alpn=h3&obfs=obfsval")
	out := &option.HysteriaOutboundOptions{}
	if err := parseHysteria(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "hy.example.com" || out.ServerPort != 443 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.AuthString != "authstring" {
		t.Errorf("auth: got %q", out.AuthString)
	}
	if out.UpMbps != 100 || out.DownMbps != 200 {
		t.Errorf("up/down: got %d/%d", out.UpMbps, out.DownMbps)
	}
	if out.TLS.ServerName != "peer-sni.com" {
		t.Errorf("TLS SNI from peer: got %q", out.TLS.ServerName)
	}
	if out.Obfs != "obfsval" {
		t.Errorf("obfs: got %q", out.Obfs)
	}
}

func TestParseHysteria_SNI_Fallback(t *testing.T) {
	u, _ := url.Parse("hy://auth@hy.example.com:443?sni=sni.com")
	out := &option.HysteriaOutboundOptions{}
	if err := parseHysteria(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TLS.ServerName != "sni.com" {
		t.Errorf("SNI: got %q, want sni.com", out.TLS.ServerName)
	}
}

func TestParseHysteria_SNI_FallbackToHost(t *testing.T) {
	u, _ := url.Parse("hy://auth@hy.example.com:443")
	out := &option.HysteriaOutboundOptions{}
	if err := parseHysteria(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TLS.ServerName != "hy.example.com" {
		t.Errorf("SNI fallback: got %q, want hy.example.com", out.TLS.ServerName)
	}
}

func TestParseHysteria2_Basic(t *testing.T) {
	u, _ := url.Parse("hy2://hy2pass@hy2.example.com:443?upmbps=50&downmbps=100&sni=hy2-sni.com&insecure=1&alpn=h3")
	out := &option.Hysteria2OutboundOptions{}
	if err := parseHysteria2(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "hy2.example.com" || out.ServerPort != 443 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.Password != "hy2pass" {
		t.Errorf("password: got %q", out.Password)
	}
	if out.UpMbps != 50 || out.DownMbps != 100 {
		t.Errorf("up/down: got %d/%d", out.UpMbps, out.DownMbps)
	}
	if out.TLS.ServerName != "hy2-sni.com" {
		t.Errorf("TLS SNI: got %q", out.TLS.ServerName)
	}
}

func TestParseHysteria2_Obfs(t *testing.T) {
	u, _ := url.Parse("hy2://pass@hy2.example.com:443?obfs=salamander&obfs-password=obfspass")
	out := &option.Hysteria2OutboundOptions{}
	if err := parseHysteria2(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Obfs == nil || out.Obfs.Type != "salamander" {
		t.Errorf("obfs type: got %+v", out.Obfs)
	}
	if out.Obfs.Password != "obfspass" {
		t.Errorf("obfs password: got %q", out.Obfs.Password)
	}
}

func TestParseHysteria2_SNI_FallbackToHost(t *testing.T) {
	u, _ := url.Parse("hy2://pass@hy2.example.com:443")
	out := &option.Hysteria2OutboundOptions{}
	if err := parseHysteria2(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TLS.ServerName != "hy2.example.com" {
		t.Errorf("SNI fallback: got %q", out.TLS.ServerName)
	}
}

func TestParseHysteria2_AllowInsecureAlias(t *testing.T) {
	u, _ := url.Parse("hy2://pass@hy2.example.com:443?allowInsecure=1")
	out := &option.Hysteria2OutboundOptions{}
	if err := parseHysteria2(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.TLS.Insecure {
		t.Errorf("expected insecure=true from allowInsecure=1")
	}
}
