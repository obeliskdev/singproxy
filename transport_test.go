package singproxy

import (
	"net/url"
	"testing"
)

func TestParseTransport(t *testing.T) {
	tests := []struct {
		name        string
		params      url.Values
		host        string
		wantType    string
		wantNil     bool
		wantErr     bool
		wantPath    string
		wantHost    string
		wantService string
	}{
		{
			name:    "empty type returns nil",
			params:  url.Values{},
			host:    "example.com",
			wantNil: true,
		},
		{
			name:    "tcp type returns nil",
			params:  url.Values{"type": {"tcp"}},
			host:    "example.com",
			wantNil: true,
		},
		{
			name:    "raw type returns nil",
			params:  url.Values{"type": {"raw"}},
			host:    "example.com",
			wantNil: true,
		},
		{
			name:     "ws transport",
			params:   url.Values{"type": {"ws"}, "path": {"/ray"}, "host": {"ws.example.com"}},
			host:     "fallback.com",
			wantType: "ws",
			wantPath: "/ray",
			wantHost: "ws.example.com",
		},
		{
			name:     "websocket alias",
			params:   url.Values{"type": {"websocket"}, "path": {"/ws"}},
			host:     "ws.example.com",
			wantType: "ws",
			wantPath: "/ws",
			wantHost: "ws.example.com",
		},
		{
			name:        "grpc transport with serviceName",
			params:      url.Values{"type": {"grpc"}, "serviceName": {"grpc-svc"}},
			host:        "grpc.example.com",
			wantType:    "grpc",
			wantService: "grpc-svc",
		},
		{
			name:        "grpc transport fallback to path",
			params:      url.Values{"type": {"grpc"}, "path": {"/grpc-path"}},
			host:        "grpc.example.com",
			wantType:    "grpc",
			wantService: "/grpc-path",
		},
		{
			name:     "http transport",
			params:   url.Values{"type": {"http"}, "path": {"/http"}, "host": {"http.example.com"}},
			host:     "fallback.com",
			wantType: "http",
			wantPath: "/http",
			wantHost: "http.example.com",
		},
		{
			name:     "httpupgrade transport",
			params:   url.Values{"type": {"httpupgrade"}, "path": {"/upgrade"}, "host": {"up.example.com"}},
			host:     "fallback.com",
			wantType: "httpupgrade",
			wantPath: "/upgrade",
			wantHost: "up.example.com",
		},
		{
			name:     "httpupgrade default path",
			params:   url.Values{"type": {"httpupgrade"}},
			host:     "up.example.com",
			wantType: "httpupgrade",
			wantPath: "/",
			wantHost: "up.example.com",
		},
		{
			name:    "xhttp returns nil (handled at factory level)",
			params:  url.Values{"type": {"xhttp"}, "path": {"/xh"}},
			host:    "x.example.com",
			wantNil: true,
		},
		{
			name:    "splithttp returns nil (handled at factory level)",
			params:  url.Values{"type": {"splithttp"}, "path": {"/sh"}},
			host:    "s.example.com",
			wantNil: true,
		},
		{
			name:     "tcp with headerType http maps to httpupgrade",
			params:   url.Values{"type": {"tcp"}, "headerType": {"http"}, "path": {"/hu"}},
			host:     "h.example.com",
			wantType: "httpupgrade",
			wantPath: "/hu",
		},
		{
			name:     "empty type with headerType http maps to httpupgrade",
			params:   url.Values{"headerType": {"http"}, "path": {"/hu2"}},
			host:     "h2.example.com",
			wantType: "httpupgrade",
			wantPath: "/hu2",
		},
		{
			name:    "invalid transport type",
			params:  url.Values{"type": {"kcp"}},
			host:    "kcp.example.com",
			wantErr: true,
		},
		{
			name:     "type with = suffix stripped",
			params:   url.Values{"type": {"ws=something"}, "path": {"/wseq"}},
			host:     "wseq.example.com",
			wantType: "ws",
			wantPath: "/wseq",
		},
		{
			name:     "type with @ suffix stripped",
			params:   url.Values{"type": {"ws@something"}, "path": {"/wsat"}},
			host:     "wsat.example.com",
			wantType: "ws",
			wantPath: "/wsat",
		},
		{
			name:     "ws falls back to host param when host empty",
			params:   url.Values{"type": {"ws"}, "path": {"/ws"}},
			host:     "fallback.example.com",
			wantType: "ws",
			wantPath: "/ws",
			wantHost: "fallback.example.com",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			transport, err := parseTransport(tc.params, tc.host)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", transport)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantNil {
				if transport != nil {
					t.Errorf("expected nil transport, got %+v", transport)
				}
				return
			}
			if transport == nil {
				t.Fatal("expected non-nil transport")
			}
			if transport.Type != tc.wantType {
				t.Errorf("Type: got %q, want %q", transport.Type, tc.wantType)
			}
			switch tc.wantType {
			case "ws":
				if transport.WebsocketOptions.Path != tc.wantPath {
					t.Errorf("WS Path: got %q, want %q", transport.WebsocketOptions.Path, tc.wantPath)
				}
				if tc.wantHost != "" {
					hdrs := transport.WebsocketOptions.Headers
					if h, ok := hdrs["Host"]; !ok || len(h) == 0 || h[0] != tc.wantHost {
						t.Errorf("WS Host header: got %v, want %q", hdrs, tc.wantHost)
					}
				}
			case "grpc":
				if transport.GRPCOptions.ServiceName != tc.wantService {
					t.Errorf("GRPC ServiceName: got %q, want %q", transport.GRPCOptions.ServiceName, tc.wantService)
				}
			case "http":
				if transport.HTTPOptions.Path != tc.wantPath {
					t.Errorf("HTTP Path: got %q, want %q", transport.HTTPOptions.Path, tc.wantPath)
				}
				if tc.wantHost != "" {
					if len(transport.HTTPOptions.Host) == 0 || transport.HTTPOptions.Host[0] != tc.wantHost {
						t.Errorf("HTTP Host: got %v, want %q", transport.HTTPOptions.Host, tc.wantHost)
					}
				}
			case "httpupgrade":
				if transport.HTTPUpgradeOptions.Path != tc.wantPath {
					t.Errorf("HTTPUpgrade Path: got %q, want %q", transport.HTTPUpgradeOptions.Path, tc.wantPath)
				}
				if tc.wantHost != "" && transport.HTTPUpgradeOptions.Host != tc.wantHost {
					t.Errorf("HTTPUpgrade Host: got %q, want %q", transport.HTTPUpgradeOptions.Host, tc.wantHost)
				}
			}
		})
	}
}
