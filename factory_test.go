package singproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestFromURL(t *testing.T) {
	realityPublicKey := "zpbDgfQxvlM2vbx3M1yM4fNC525q_g8yHiTPikDqjhs"
	realityShortID := "a1b2c3d4e5f6a7b8"
	wgPrivateKey := "gCrpA4g8MvjGn85nslmf8Uv25soA9j+R5f6vOa3a41E="
	wgPublicKey := "w9q0T7aiJ27v39yO85yD5jY3kQ1Oa2u5b8a/cDef3gY="

	testCases := []struct {
		name      string
		url       string
		shouldErr bool
		validate  func(t *testing.T, p Proxy)
	}{
		{
			name: "Schemaless HTTP",
			url:  "user:pass@schemaless.example.com:8080",
			validate: func(t *testing.T, p Proxy) {
				opts := p.(*SingBoxProxy).options.(*option.HTTPOutboundOptions)
				if opts.Server != "schemaless.example.com" || opts.ServerPort != 8080 || opts.Username != "user" || opts.Password != "pass" {
					t.Errorf("Schemaless HTTP parsing failed. Got %+v", opts)
				}
			},
		},
		{
			name: "VLESS with Reality",
			url:  "vless://a-vless-uuid@reality.example.com:443?security=reality&sni=sni.example.com&fp=chrome&pbk=" + realityPublicKey + "&sid=" + realityShortID + "&type=tcp#VLESS-Reality",
			validate: func(t *testing.T, p Proxy) {
				opts := p.(*SingBoxProxy).options.(*option.VLESSOutboundOptions)
				if opts.Server != "reality.example.com" || opts.UUID != "a-vless-uuid" || !opts.TLS.Enabled || !opts.TLS.Reality.Enabled || opts.TLS.Reality.PublicKey != realityPublicKey || opts.TLS.ServerName != "sni.example.com" {
					t.Errorf("VLESS+Reality parsing failed. Got %+v", opts)
				}
			},
		},
		{
			name: "WireGuard",
			url:  "wireguard://" + url.PathEscape(wgPrivateKey) + "@wg.example.com:51820?publickey=" + url.PathEscape(wgPublicKey) + "&address=192.168.1.1/32&address=fd00::1/128",
			validate: func(t *testing.T, p Proxy) {
				opts := p.(*SingBoxProxy).options.(*option.WireGuardEndpointOptions)
				expectedAddrs := []string{"192.168.1.1/32", "fd00::1/128"}
				if len(opts.Address) != len(expectedAddrs) {
					t.Fatalf("WireGuard parsing failed. Expected %d addresses, got %d", len(expectedAddrs), len(opts.Address))
				}
				for i := range opts.Address {
					if opts.Address[i].String() != expectedAddrs[i] {
						t.Errorf("WireGuard address mismatch. Got %s, expected %s", opts.Address[i].String(), expectedAddrs[i])
					}
				}
				if len(opts.Peers) != 1 {
					t.Fatalf("WireGuard parsing failed. Expected 1 peer, got %d", len(opts.Peers))
				}
				if opts.Peers[0].Address != "wg.example.com" || opts.Peers[0].Port != 51820 {
					t.Errorf("WireGuard peer endpoint mismatch. Got %s:%d", opts.Peers[0].Address, opts.Peers[0].Port)
				}
				if opts.Peers[0].PublicKey != wgPublicKey {
					t.Errorf("WireGuard peer public key mismatch. Got %s", opts.Peers[0].PublicKey)
				}
			},
		},
		{
			name: "VLESS+WS+TLS with mux",
			url:  "vless://ws-uuid@ws.example.com:443?encryption=none&security=tls&sni=ws.example.com&type=ws&path=/ray&host=ws.example.com&alpn=h2&fp=chrome&mux=8&allow_insecure=1#vless-ws",
			validate: func(t *testing.T, p Proxy) {
				opts := p.(*SingBoxProxy).options.(*option.VLESSOutboundOptions)
				if opts.Server != "ws.example.com" || opts.ServerPort != 443 || opts.UUID != "ws-uuid" {
					t.Errorf("VLESS WS server/uuid mismatch. Got %+v", opts)
				}
				if opts.Transport == nil || opts.Transport.Type != "ws" {
					t.Fatalf("VLESS WS transport should be ws")
				}
				if opts.Transport.WebsocketOptions.Path != "/ray" {
					t.Errorf("VLESS WS path mismatch. Got %s", opts.Transport.WebsocketOptions.Path)
				}
				if opts.TLS == nil || !opts.TLS.Enabled || opts.TLS.ServerName != "ws.example.com" {
					t.Errorf("VLESS WS TLS mismatch. Got %+v", opts.TLS)
				}
				if !opts.TLS.Insecure {
					t.Errorf("VLESS WS allow_insecure=1 should set Insecure=true")
				}
				if len(opts.TLS.ALPN) != 1 || opts.TLS.ALPN[0] != "h2" {
					t.Errorf("VLESS WS ALPN mismatch. Got %v", opts.TLS.ALPN)
				}
				if opts.Multiplex == nil || !opts.Multiplex.Enabled {
					t.Fatalf("VLESS WS multiplex should be enabled")
				}
				if opts.Multiplex.MaxStreams != 8 {
					t.Errorf("VLESS WS mux max_streams should be 8. Got %d", opts.Multiplex.MaxStreams)
				}
			},
		},
		{
			name: "VLESS+HTTP transport",
			url:  "vless://http-uuid@http.example.com:443?encryption=none&security=tls&sni=http.example.com&type=http&path=/http&host=http.example.com#vless-http",
			validate: func(t *testing.T, p Proxy) {
				opts := p.(*SingBoxProxy).options.(*option.VLESSOutboundOptions)
				if opts.Transport == nil || opts.Transport.Type != "http" {
					t.Fatalf("VLESS HTTP transport should be http")
				}
				if opts.Transport.HTTPOptions.Path != "/http" {
					t.Errorf("VLESS HTTP path mismatch. Got %s", opts.Transport.HTTPOptions.Path)
				}
			},
		},
		{
			name:      "VLESS unsupported encryption",
			url:       "vless://uuid@bad.example.com:443?encryption=aes-128-gcm",
			shouldErr: true,
		},
		{
			name:      "Invalid Scheme",
			url:       "invalid-scheme://whatever",
			shouldErr: true,
		},
		{
			name: "Trojan-Go aliases",
			url:  "trojan-go://pass@trojango.example.com:443?ssl_verify=false&ssl_sni=trojango.example.com&type=ws&path=/ws",
			validate: func(t *testing.T, p Proxy) {
				opts := p.(*SingBoxProxy).options.(*option.TrojanOutboundOptions)
				if opts.Server != "trojango.example.com" || opts.ServerPort != 443 || opts.Password != "pass" {
					t.Errorf("Trojan-Go server/password mismatch. Got %+v", opts)
				}
				if opts.TLS == nil || !opts.TLS.Enabled {
					t.Fatalf("Trojan-Go TLS not enabled")
				}
				if !opts.TLS.Insecure {
					t.Errorf("Trojan-Go ssl_verify=false should map to insecure=true")
				}
				if opts.TLS.ServerName != "trojango.example.com" {
					t.Errorf("Trojan-Go ssl_sni should map to sni. Got ServerName=%s", opts.TLS.ServerName)
				}
				if opts.Transport == nil || opts.Transport.Type != "ws" {
					t.Errorf("Trojan-Go transport should be ws. Got %+v", opts.Transport)
				}
			},
		},
		{
			name: "SOCKS4a",
			url:  "socks4a://host.example.com:1080",
			validate: func(t *testing.T, p Proxy) {
				opts := p.(*SingBoxProxy).options.(*option.SOCKSOutboundOptions)
				if opts.Server != "host.example.com" || opts.ServerPort != 1080 || opts.Version != "4" {
					t.Errorf("SOCKS4a parsing failed. Got %+v", opts)
				}
			},
		},
		{
			name: "SOCKS legacy base64",
			url:  "socks://" + base64.RawStdEncoding.EncodeToString([]byte("user:pass@socksb64.example.com:1080")),
			validate: func(t *testing.T, p Proxy) {
				opts := p.(*SingBoxProxy).options.(*option.SOCKSOutboundOptions)
				if opts.Server != "socksb64.example.com" || opts.ServerPort != 1080 || opts.Version != "5" {
					t.Errorf("SOCKS legacy base64 parsing failed. Got %+v", opts)
				}
				if opts.Username != "user" || opts.Password != "pass" {
					t.Errorf("SOCKS legacy base64 auth mismatch. Got user=%s pass=%s", opts.Username, opts.Password)
				}
			},
		},
		{
			name:      "ShadowsocksR",
			url:       "ssr://" + base64.StdEncoding.EncodeToString([]byte("ssr.example.com:8388:auth_aes128_md5:aes-256-cfb:http_simple:"+base64.StdEncoding.EncodeToString([]byte("ssrpass")))),
			shouldErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			proxy, err := FromURL(Config{DialTimeout: 8 * time.Second}, tc.url)
			if tc.shouldErr {
				if err == nil {
					t.Errorf("Expected an error, but got none")
				}
				return
			}
			if err != nil {
				skipIfFeatureMissing(t, err)
				t.Fatalf("Did not expect an error, but got: %v", err)
			}
			if proxy == nil {
				t.Fatal("Expected a proxy instance, but got nil")
			}
			if tc.validate != nil {
				tc.validate(t, proxy)
			}
		})
	}
}

func TestDirectConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live network test in short mode")
	}

	proxy, err := FromURL(Config{DialTimeout: 8 * time.Second}, "direct")
	if err != nil {
		t.Fatalf("Failed to create direct proxy: %v", err)
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				tcpAddr, err := net.ResolveTCPAddr(network, addr)
				if err != nil {
					return nil, err
				}

				return proxy.DialContextAddr(ctx, network, tcpAddr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://httpbun.com/get", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("User-Agent", "singproxy-Test-Client")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected status code 200, but got %d. Body: %s", resp.StatusCode, string(bodyBytes))
	}
	t.Log("Successfully connected to httpbin.org through direct proxy.")
}
