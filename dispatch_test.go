package singproxy

import "testing"

func TestGetProxyType(t *testing.T) {
	tests := []struct {
		scheme  string
		want    string
		wantErr bool
	}{
		{"vmess", "vmess", false},
		{"VMESS", "vmess", false},
		{"Vmess", "vmess", false},
		{"http", "http", false},
		{"https", "http", false},
		{"http2", "http", false},
		{"vless", "vless", false},
		{"trojan", "trojan", false},
		{"trojan-go", "trojan", false},
		{"ss", "shadowsocks", false},
		{"shadowsocks", "shadowsocks", false},
		{"ssr", "shadowsocksr", false},
		{"shadowsocksr", "shadowsocksr", false},
		{"tuic", "tuic", false},
		{"hy", "hysteria", false},
		{"hysteria", "hysteria", false},
		{"hy2", "hysteria2", false},
		{"hysteria2", "hysteria2", false},
		{"ssh", "ssh", false},
		{"socks", "socks", false},
		{"socks5", "socks", false},
		{"socks4", "socks", false},
		{"socks4a", "socks", false},
		{"wireguard", "wireguard", false},
		{"direct", "direct", false},
		{"tor", "tor", false},
		{"anytls", "anytls", false},
		{"atls", "anytls", false},
		{"shadowtls", "shadowtls", false},
		{"naive", "naive", false},
		{"naive+https", "naive", false},
		{"unknown-scheme", "", true},
		{"", "", true},
		{"foo", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.scheme, func(t *testing.T) {
			got, err := getProxyType(tc.scheme)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got %q", tc.scheme, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.scheme, err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
