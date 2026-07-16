package singproxy

import (
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseVLESS_Basic(t *testing.T) {
	u, _ := url.Parse("vless://uuid-1234@vless.example.com:443?encryption=none")
	out := &option.VLESSOutboundOptions{}
	if err := parseVLESS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Server != "vless.example.com" || out.ServerPort != 443 {
		t.Errorf("server/port: got %s:%d", out.Server, out.ServerPort)
	}
	if out.UUID != "uuid-1234" {
		t.Errorf("UUID: got %q", out.UUID)
	}
	if out.Flow != "" {
		t.Errorf("Flow: got %q, want empty", out.Flow)
	}
}

func TestParseVLESS_Flow(t *testing.T) {
	u, _ := url.Parse("vless://uuid@vless.example.com:443?encryption=none&flow=xtls-rprx-vision")
	out := &option.VLESSOutboundOptions{}
	if err := parseVLESS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow: got %q, want xtls-rprx-vision", out.Flow)
	}
}

func TestParseVLESS_EncryptionNone(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host:443?encryption=none")
	out := &option.VLESSOutboundOptions{}
	if err := parseVLESS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseVLESS_EncryptionGarbageTrailingEqual(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host:80?encryption=none=@GHALAGYANN,@GHALAGYANN")
	out := &option.VLESSOutboundOptions{}
	if err := parseVLESS(out, u); err != nil {
		t.Fatalf("unexpected error for encryption=none=garbage: %v", err)
	}
}

func TestParseVLESS_EncryptionMlkem(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host:443?encryption=mlkem768x25519plus.native.1rtt.base64data")
	out := &option.VLESSOutboundOptions{}
	if err := parseVLESS(out, u); err != nil {
		t.Fatalf("unexpected error for mlkem encryption: %v", err)
	}
}

func TestParseVLESS_UnsupportedEncryption(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host:443?encryption=aes-128-gcm")
	out := &option.VLESSOutboundOptions{}
	err := parseVLESS(out, u)
	if err == nil {
		t.Fatal("expected error for unsupported encryption")
	}
}

func TestParseVLESS_PacketEncodingXudp(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host:443?encryption=none&packetEncoding=xudp")
	out := &option.VLESSOutboundOptions{}
	if err := parseVLESS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.PacketEncoding == nil || *out.PacketEncoding != "xudp" {
		t.Errorf("PacketEncoding: got %v, want xudp", out.PacketEncoding)
	}
}

func TestParseVLESS_PacketEncodingOther(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host:443?encryption=none&packetEncoding=none")
	out := &option.VLESSOutboundOptions{}
	if err := parseVLESS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.PacketEncoding != nil {
		t.Errorf("PacketEncoding: got %v, want nil", out.PacketEncoding)
	}
}

func TestParseVLESS_InvalidPort(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host:abc")
	if u == nil {
		return
	}
	out := &option.VLESSOutboundOptions{}
	err := parseVLESS(out, u)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestParseVLESS_NoHostPort(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host")
	if u == nil {
		return
	}
	out := &option.VLESSOutboundOptions{}
	err := parseVLESS(out, u)
	if err == nil {
		t.Fatal("expected error for missing port")
	}
}

func TestParseVLESS_WS_Transport(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host:443?encryption=none&type=ws&path=/ray&host=ws-host.com")
	out := &option.VLESSOutboundOptions{}
	if err := parseVLESS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Transport == nil || out.Transport.Type != "ws" {
		t.Fatalf("transport: expected ws, got %+v", out.Transport)
	}
	if out.Transport.WebsocketOptions.Path != "/ray" {
		t.Errorf("path: got %q, want /ray", out.Transport.WebsocketOptions.Path)
	}
}

func TestParseVLESS_GRPC_Transport(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host:443?encryption=none&type=grpc&serviceName=grpc-svc")
	out := &option.VLESSOutboundOptions{}
	if err := parseVLESS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Transport == nil || out.Transport.Type != "grpc" {
		t.Fatalf("transport: expected grpc, got %+v", out.Transport)
	}
	if out.Transport.GRPCOptions.ServiceName != "grpc-svc" {
		t.Errorf("serviceName: got %q", out.Transport.GRPCOptions.ServiceName)
	}
}

func TestParseVLESS_TLS(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host:443?encryption=none&security=tls&sni=sni.com&fp=chrome")
	out := &option.VLESSOutboundOptions{}
	if err := parseVLESS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.TLS == nil || !out.TLS.Enabled || out.TLS.ServerName != "sni.com" {
		t.Errorf("TLS: got %+v", out.TLS)
	}
}

func TestParseVLESS_Mux(t *testing.T) {
	u, _ := url.Parse("vless://uuid@host:443?encryption=none&mux=8")
	out := &option.VLESSOutboundOptions{}
	if err := parseVLESS(out, u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Multiplex == nil || !out.Multiplex.Enabled || out.Multiplex.MaxStreams != 8 {
		t.Errorf("Multiplex: got %+v", out.Multiplex)
	}
}
