package singproxy

import "testing"

// TestSupportedFormatsRoundTrip covers the common real-world shape of
// every supported scheme, guarding against regressions where a scheme
// is registered but its parser was never wired up.
func TestSupportedFormatsRoundTrip(t *testing.T) {
	valid := []struct {
		name string
		url  string
	}{
		{"direct", "direct"},
		{"http", "http://user:pass@example.com:8080"},
		{"https", "https://user:pass@example.com:443"},
		{"http2", "http2://user:pass@example.com:443"},
		{"socks5", "socks5://user:pass@example.com:1080"},
		{"socks4", "socks4://1.2.3.4:1080"},
		{"socks with base64 auth", "socks://dXNlcjpwYXNz@1.2.3.4:1080"},
		{"ss sip002", "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8080"},
		{"ss plugin", "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8080?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com"},
		{"vless ws tls", "vless://12345678-1234-1234-1234-123456789abc@example.com:443?type=ws&path=%2Fpath&security=tls&sni=example.com"},
		{"vless grpc", "vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&type=grpc&serviceName=svc&fp=chrome"},
		{"vless reality", "vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=reality&pbk=Q-0QMHseZjIK3yHwmXW-ORA2RgrR2jjgYUbK06OFEMc&sid=abcd1234&fp=chrome"},
		{"trojan", "trojan://password@example.com:443?sni=example.com"},
		{"ssh", "ssh://user@example.com:22"},
		{"hysteria2 obfs", "hysteria2://password@example.com:443?obfs=salamander&obfs-password=abc&insecure=1"},
		{"tuic", "tuic://12345678-1234-1234-1234-123456789abc:pass@example.com:443?sni=example.com&congestion_control=bbr&udp_relay_mode=native"},
		{"vmess ws", "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OWFiYyIsIm5ldCI6IndzIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii93cyIsInRscyI6InRscyJ9"},
		{"vmess xhttp", "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OWFiYyIsIm5ldCI6InNwbGl0aHR0cCIsImhvc3QiOiJleGFtcGxlLmNvbSIsInBhdGgiOiIveCIsInRscyI6InRscyJ9"},
	}

	for _, c := range valid {
		t.Run(c.name, func(t *testing.T) {
			p, err := FromURL(Config{}, c.url)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			defer p.Close()

			if p.String() == "" {
				t.Error("String() is empty")
			}
			if p.Addr() == nil {
				t.Error("Addr() is nil")
			}
		})
	}
}

// TestUnsupportedSchemesRejected ensures unknown schemes fail cleanly
// at parse time rather than producing broken proxies.
func TestUnsupportedSchemesRejected(t *testing.T) {
	for _, u := range []string{
		"unknown://example.com:443",
		"vmess://%%%invalid-base64",
		"ss://",
		"socks://",
		"tor://",
		"vless://",
	} {
		if _, err := FromURL(Config{}, u); err == nil {
			t.Errorf("expected error for %q", u)
		}
	}
}
