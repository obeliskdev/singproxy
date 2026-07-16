package singproxy

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseShadowsocks_SIP002(t *testing.T) {
	userInfo := base64.RawStdEncoding.EncodeToString([]byte("aes-256-gcm:password123"))
	u, _ := url.Parse("ss://" + userInfo + "@ss.example.com:8388")
	out := &option.ShadowsocksOutboundOptions{}
	if err := parseShadowsocks(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "ss.example.com" || out.ServerPort != 8388 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.Method != "aes-256-gcm" {
		t.Errorf("method: got %q, want aes-256-gcm", out.Method)
	}
	if out.Password != "password123" {
		t.Errorf("password: got %q, want password123", out.Password)
	}
}

func TestParseShadowsocks_PlaintextUserinfo(t *testing.T) {
	u, _ := url.Parse("ss://aes-256-gcm:mypassword@ss.example.com:8388")
	out := &option.ShadowsocksOutboundOptions{}
	if err := parseShadowsocks(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Method != "aes-256-gcm" || out.Password != "mypassword" {
		t.Errorf("got method=%q password=%q", out.Method, out.Password)
	}
}

func TestParseShadowsocks_PlaintextPasswordOnly(t *testing.T) {
	u, _ := url.Parse("ss://justpassword@ss.example.com:8388")
	out := &option.ShadowsocksOutboundOptions{}
	if err := parseShadowsocks(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Password != "justpassword" {
		t.Errorf("password: got %q, want justpassword", out.Password)
	}
	if out.Method != "aes-256-gcm" {
		t.Errorf("method default: got %q, want aes-256-gcm", out.Method)
	}
}

func TestParseShadowsocks_LegacyBase64(t *testing.T) {
	legacy := base64.RawStdEncoding.EncodeToString([]byte("aes-256-gcm:password@ss-legacy.example.com:8388"))
	u, _ := url.Parse("ss://" + legacy)
	out := &option.ShadowsocksOutboundOptions{}
	if err := parseShadowsocks(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "ss-legacy.example.com" || out.ServerPort != 8388 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.Method != "aes-256-gcm" || out.Password != "password" {
		t.Errorf("method/password: got %q/%q", out.Method, out.Password)
	}
}

func TestParseShadowsocks_EncryptionNone(t *testing.T) {
	u, _ := url.Parse("ss://user:pass@ss.example.com:8388?encryption=none")
	out := &option.ShadowsocksOutboundOptions{}
	if err := parseShadowsocks(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Method != "none" {
		t.Errorf("method: got %q, want none", out.Method)
	}
}

func TestParseShadowsocks_Plugin(t *testing.T) {
	u, _ := url.Parse("ss://user:pass@ss.example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dfoo.com")
	out := &option.ShadowsocksOutboundOptions{}
	if err := parseShadowsocks(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Plugin != "obfs-local" {
		t.Errorf("plugin: got %q, want obfs-local", out.Plugin)
	}
	if out.PluginOptions != "obfs=http;obfs-host=foo.com" {
		t.Errorf("plugin opts: got %q", out.PluginOptions)
	}
}

func TestParseShadowsocks_JSONConfig(t *testing.T) {
	jsonStr := `{"add":"ss-json.example.com","port":8443,"id":"my-password","net":"ws","host":"ss-host.com","path":"/ws","tls":"tls","sni":"ss-sni.com"}`
	b64 := base64.RawStdEncoding.EncodeToString([]byte(jsonStr))
	u, _ := url.Parse("ss://" + b64)
	out := &option.ShadowsocksOutboundOptions{}
	if err := parseShadowsocks(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "ss-json.example.com" || out.ServerPort != 8443 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.Method != "aes-256-gcm" {
		t.Errorf("method: got %q, want aes-256-gcm", out.Method)
	}
	if out.Password != "my-password" {
		t.Errorf("password: got %q, want my-password", out.Password)
	}
}

func TestParseShadowsocks_JSONConfigEncryptionNone(t *testing.T) {
	jsonStr := `{"add":"ss-none.example.com","port":8443,"encryption":"none","id":"pw"}`
	b64 := base64.RawStdEncoding.EncodeToString([]byte(jsonStr))
	u, _ := url.Parse("ss://" + b64)
	out := &option.ShadowsocksOutboundOptions{}
	if err := parseShadowsocks(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Method != "none" {
		t.Errorf("method: got %q, want none", out.Method)
	}
}

func TestParseShadowsocks_JSONConfigMissingMethod(t *testing.T) {
	jsonStr := `{"add":"ss-bad.example.com","port":8443}`
	b64 := base64.RawStdEncoding.EncodeToString([]byte(jsonStr))
	u, _ := url.Parse("ss://" + b64)
	out := &option.ShadowsocksOutboundOptions{}
	err := parseShadowsocks(out, u)
	if err == nil {
		t.Fatal("expected error for missing method")
	}
}

func TestParseShadowsocks_InvalidPort(t *testing.T) {
	u, _ := url.Parse("ss://user:pass@ss.example.com:abc")
	if u == nil || u.Host == "" {
		return
	}
	out := &option.ShadowsocksOutboundOptions{}
	err := parseShadowsocks(out, u)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestParseShadowsocks_NoHostPort(t *testing.T) {
	u, _ := url.Parse("ss://user:pass")
	if u == nil {
		return
	}
	out := &option.ShadowsocksOutboundOptions{}
	err := parseShadowsocks(out, u)
	if err == nil {
		t.Fatal("expected error for missing host:port")
	}
}

func TestParseShadowsocksR_Basic(t *testing.T) {
	payload := "ssr.example.com:8388:auth_aes128_md5:aes-256-cfb:http_simple:" + base64.RawStdEncoding.EncodeToString([]byte("ssrpass"))
	b64 := base64.RawStdEncoding.EncodeToString([]byte(payload))
	u, _ := url.Parse("ssr://" + b64)
	out := &option.ShadowsocksROutboundOptions{}
	if err := parseShadowsocksR(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "ssr.example.com" || out.ServerPort != 8388 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.Protocol != "auth_aes128_md5" {
		t.Errorf("protocol: got %q", out.Protocol)
	}
	if out.Method != "aes-256-cfb" {
		t.Errorf("method: got %q", out.Method)
	}
	if out.Obfs != "http_simple" {
		t.Errorf("obfs: got %q", out.Obfs)
	}
	if out.Password != "ssrpass" {
		t.Errorf("password: got %q, want ssrpass", out.Password)
	}
}

func TestParseShadowsocksR_TooFewFields(t *testing.T) {
	b64 := base64.RawStdEncoding.EncodeToString([]byte("host:port:proto"))
	u, _ := url.Parse("ssr://" + b64)
	out := &option.ShadowsocksROutboundOptions{}
	err := parseShadowsocksR(out, u)
	if err == nil {
		t.Fatal("expected error for too few fields")
	}
}

func TestParseShadowsocksR_InvalidBase64(t *testing.T) {
	u, _ := url.Parse("ssr://!!!invalid!!!")
	out := &option.ShadowsocksROutboundOptions{}
	err := parseShadowsocksR(out, u)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseShadowsocksR_WithParams(t *testing.T) {
	payload := "ssr.example.com:8388:auth_aes128_md5:aes-256-cfb:http_simple:" + base64.RawStdEncoding.EncodeToString([]byte("pass"))
	b64 := base64.RawStdEncoding.EncodeToString([]byte(payload))
	u, _ := url.Parse("ssr://" + b64 + "?obfsparam=" + base64.RawStdEncoding.EncodeToString([]byte("obfsparam-value")) + "&protoparam=" + base64.RawStdEncoding.EncodeToString([]byte("proto-param")))
	out := &option.ShadowsocksROutboundOptions{}
	if err := parseShadowsocksR(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.ObfsParam != "obfsparam-value" {
		t.Errorf("obfsParam: got %q, want obfsparam-value", out.ObfsParam)
	}
	if out.ProtocolParam != "proto-param" {
		t.Errorf("protocolParam: got %q, want proto-param", out.ProtocolParam)
	}
}
