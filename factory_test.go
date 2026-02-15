package singproxy

import (
	"context"
	"crypto/tls"
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
				opts := p.(*SingBoxProxy).options.(*option.LegacyWireGuardOutboundOptions)
				expectedAddrs := []string{"192.168.1.1/32", "fd00::1/128"}
				if len(opts.LocalAddress) != len(expectedAddrs) {
					t.Fatalf("WireGuard parsing failed. Expected %d addresses, got %d", len(expectedAddrs), len(opts.LocalAddress))
				}
				for i := range opts.LocalAddress {
					if opts.LocalAddress[i].String() != expectedAddrs[i] {
						t.Errorf("WireGuard address mismatch. Got %s, expected %s", opts.LocalAddress[i].String(), expectedAddrs[i])
					}
				}
			},
		},
		{
			name:      "Invalid Scheme",
			url:       "invalid-scheme://whatever",
			shouldErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			proxy, err := FromURL(time.Second*8, tc.url)
			if tc.shouldErr {
				if err == nil {
					t.Errorf("Expected an error, but got none")
				}
				return
			}
			if err != nil {
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

	proxy, err := FromURL(time.Second*8, "direct")
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

				return proxy.DialContext(ctx, network, tcpAddr)
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
