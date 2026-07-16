package singproxy

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func makeVMessB64(t *testing.T, jsonStr string) string {
	t.Helper()
	return base64.RawStdEncoding.EncodeToString([]byte(jsonStr))
}

func TestParseVMessBase64_StringFields(t *testing.T) {
	jsonStr := `{"v":"2","ps":"test","add":"vmess.example.com","port":"443","id":"uuid-1234","aid":"0","scy":"auto","net":"tcp","type":"none","host":"","path":"","tls":"none","sni":"","alpn":"","fp":""}`
	out := &option.VMessOutboundOptions{}
	if err := parseVMessBase64(out, makeVMessB64(t, jsonStr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "vmess.example.com" || out.ServerPort != 443 {
		t.Errorf("server/port: got %s:%d, want vmess.example.com:443", out.Server, out.ServerPort)
	}
	if out.UUID != "uuid-1234" {
		t.Errorf("UUID: got %q, want uuid-1234", out.UUID)
	}
	if out.AlterId != 0 {
		t.Errorf("AlterId: got %d, want 0", out.AlterId)
	}
	if out.Security != "auto" {
		t.Errorf("Security: got %q, want auto", out.Security)
	}
	if out.Transport != nil {
		t.Errorf("Transport: expected nil for tcp, got %+v", out.Transport)
	}
	if out.TLS != nil {
		t.Errorf("TLS: expected nil for tls=none, got %+v", out.TLS)
	}
}

func TestParseVMessBase64_NumberFields(t *testing.T) {
	jsonStr := `{"v":2,"add":"vmess.example.com","port":8080,"id":"uuid-1234","aid":64,"net":"tcp","type":null,"host":null,"path":"/","tls":false,"sni":null,"alpn":null,"fp":null}`
	out := &option.VMessOutboundOptions{}
	if err := parseVMessBase64(out, makeVMessB64(t, jsonStr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.ServerPort != 8080 {
		t.Errorf("port: got %d, want 8080", out.ServerPort)
	}
	if out.AlterId != 64 {
		t.Errorf("AlterId: got %d, want 64", out.AlterId)
	}
}

func TestParseVMessBase64_NullFields(t *testing.T) {
	jsonStr := `{"v":null,"add":"vmess.example.com","port":"443","id":"uuid","aid":null,"net":null,"type":null,"host":null,"path":null,"tls":null,"sni":null,"alpn":null,"fp":null}`
	out := &option.VMessOutboundOptions{}
	if err := parseVMessBase64(out, makeVMessB64(t, jsonStr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Transport != nil {
		t.Errorf("Transport: expected nil for net=null, got %+v", out.Transport)
	}
	if out.TLS != nil {
		t.Errorf("TLS: expected nil for tls=null, got %+v", out.TLS)
	}
}

func TestParseVMessBase64_WS(t *testing.T) {
	jsonStr := `{"v":"2","add":"ws.example.com","port":"443","id":"uuid","aid":"0","net":"ws","host":"ws-host.com","path":"/ray","tls":"tls","sni":"sni.com","alpn":"h2","fp":"chrome"}`
	out := &option.VMessOutboundOptions{}
	if err := parseVMessBase64(out, makeVMessB64(t, jsonStr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Transport == nil || out.Transport.Type != "ws" {
		t.Fatalf("Transport: expected ws, got %+v", out.Transport)
	}
	if out.Transport.WebsocketOptions.Path != "/ray" {
		t.Errorf("WS path: got %q, want /ray", out.Transport.WebsocketOptions.Path)
	}
	if out.TLS == nil || !out.TLS.Enabled {
		t.Fatal("expected enabled TLS")
	}
	if out.TLS.ServerName != "sni.com" {
		t.Errorf("TLS SNI: got %q, want sni.com", out.TLS.ServerName)
	}
}

func TestParseVMessBase64_GRPC(t *testing.T) {
	jsonStr := `{"v":"2","add":"grpc.example.com","port":"443","id":"uuid","aid":"0","net":"grpc","serviceName":"grpc-svc","tls":"tls"}`
	out := &option.VMessOutboundOptions{}
	if err := parseVMessBase64(out, makeVMessB64(t, jsonStr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Transport == nil || out.Transport.Type != "grpc" {
		t.Fatalf("Transport: expected grpc, got %+v", out.Transport)
	}
	if out.Transport.GRPCOptions.ServiceName != "grpc-svc" {
		t.Errorf("GRPC serviceName: got %q, want grpc-svc", out.Transport.GRPCOptions.ServiceName)
	}
}

func TestParseVMessBase64_GRPC_FallbackToPath(t *testing.T) {
	jsonStr := `{"v":"2","add":"grpc.example.com","port":"443","id":"uuid","aid":"0","net":"grpc","path":"/grpc-fallback","tls":""}`
	out := &option.VMessOutboundOptions{}
	if err := parseVMessBase64(out, makeVMessB64(t, jsonStr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Transport.GRPCOptions.ServiceName != "/grpc-fallback" {
		t.Errorf("GRPC fallback: got %q, want /grpc-fallback", out.Transport.GRPCOptions.ServiceName)
	}
}

func TestParseVMessBase64_HTTPUpgrade(t *testing.T) {
	jsonStr := `{"v":"2","add":"hu.example.com","port":"443","id":"uuid","aid":"0","net":"httpupgrade","host":"hu-host.com","path":"/hu","tls":""}`
	out := &option.VMessOutboundOptions{}
	if err := parseVMessBase64(out, makeVMessB64(t, jsonStr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Transport == nil || out.Transport.Type != "httpupgrade" {
		t.Fatalf("Transport: expected httpupgrade, got %+v", out.Transport)
	}
	if out.Transport.HTTPUpgradeOptions.Host != "hu-host.com" {
		t.Errorf("HTTPUpgrade host: got %q, want hu-host.com", out.Transport.HTTPUpgradeOptions.Host)
	}
}

func TestParseVMessBase64_HTTP(t *testing.T) {
	jsonStr := `{"v":"2","add":"http.example.com","port":"443","id":"uuid","aid":"0","net":"http","host":"http-host.com","path":"/http","tls":""}`
	out := &option.VMessOutboundOptions{}
	if err := parseVMessBase64(out, makeVMessB64(t, jsonStr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Transport == nil || out.Transport.Type != "http" {
		t.Fatalf("Transport: expected http, got %+v", out.Transport)
	}
	if out.Transport.HTTPOptions.Path != "/http" {
		t.Errorf("HTTP path: got %q, want /http", out.Transport.HTTPOptions.Path)
	}
}

func TestParseVMessBase64_UnsupportedNetwork(t *testing.T) {
	jsonStr := `{"v":"2","add":"bad.example.com","port":"443","id":"uuid","aid":"0","net":"kcp"}`
	out := &option.VMessOutboundOptions{}
	err := parseVMessBase64(out, makeVMessB64(t, jsonStr))
	if err == nil {
		t.Fatal("expected error for unsupported network kcp")
	}
}

func TestParseVMessBase64_InvalidBase64(t *testing.T) {
	out := &option.VMessOutboundOptions{}
	err := parseVMessBase64(out, "!!!invalid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseVMessBase64_InvalidJSON(t *testing.T) {
	out := &option.VMessOutboundOptions{}
	bad := base64.RawStdEncoding.EncodeToString([]byte("not-json"))
	err := parseVMessBase64(out, bad)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseVMessBase64_TLSFromSecurity(t *testing.T) {
	jsonStr := `{"v":"2","add":"tls.example.com","port":"443","id":"uuid","aid":"0","net":"tcp","security":"tls","sni":"sec.com"}`
	out := &option.VMessOutboundOptions{}
	if err := parseVMessBase64(out, makeVMessB64(t, jsonStr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TLS == nil || !out.TLS.Enabled {
		t.Fatal("expected TLS enabled from security=tls")
	}
	if out.TLS.ServerName != "sec.com" {
		t.Errorf("TLS SNI: got %q, want sec.com", out.TLS.ServerName)
	}
}

func TestParseVMessBase64_TLSFallbackToHost(t *testing.T) {
	jsonStr := `{"v":"2","add":"tls.example.com","port":"443","id":"uuid","aid":"0","net":"tcp","tls":"tls","host":"host-fallback.com"}`
	out := &option.VMessOutboundOptions{}
	if err := parseVMessBase64(out, makeVMessB64(t, jsonStr)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TLS.ServerName != "host-fallback.com" {
		t.Errorf("TLS SNI fallback: got %q, want host-fallback.com", out.TLS.ServerName)
	}
}

func TestParseVMess_OpaqueReconstruction(t *testing.T) {
	jsonStr := `{"v":"2","add":"recon.example.com","port":"443","id":"uuid","aid":"0","net":"tcp","path":"/custom_config?ed=2560"}`
	b64 := base64.RawStdEncoding.EncodeToString([]byte(jsonStr))
	u, _ := url.Parse("vmess://" + b64)
	out := &option.VMessOutboundOptions{}
	if err := parseVMess(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "recon.example.com" {
		t.Errorf("Server: got %q, want recon.example.com", out.Server)
	}
}

func TestParseVMess_UnrecognizedFormat(t *testing.T) {
	u, _ := url.Parse("vmess://user@host:443")
	out := &option.VMessOutboundOptions{}
	err := parseVMess(out, u)
	if err == nil {
		t.Fatal("expected error for unrecognized vmess format")
	}
}
