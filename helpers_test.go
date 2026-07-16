package singproxy

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParsePort(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    uint16
		wantErr bool
	}{
		{"string valid", "8080", 8080, false},
		{"string zero", "0", 0, false},
		{"string max", "65535", 65535, false},
		{"string empty", "", 0, true},
		{"string invalid", "abc", 0, true},
		{"string overflow", "99999", 0, true},
		{"int", 443, 443, false},
		{"int64", int64(80), 80, false},
		{"uint16", uint16(443), 443, false},
		{"float64 whole", float64(8080), 8080, false},
		{"float64 fractional", float64(8080.5), 0, true},
		{"nil", nil, 0, true},
		{"json.Number", json.Number("9090"), 9090, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePort(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  bool
	}{
		{"string true", "true", true},
		{"string false", "false", false},
		{"string 1", "1", true},
		{"string 0", "0", false},
		{"string empty", "", false},
		{"string random", "yes", false},
		{"bool true", true, true},
		{"bool false", false, false},
		{"int positive", 1, true},
		{"int zero", 0, false},
		{"int negative", -1, false},
		{"nil", nil, false},
		{"float", 1.0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseBool(tc.input)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseAlterID(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    int
		wantErr bool
	}{
		{"nil", nil, 0, false},
		{"string number", "64", 64, false},
		{"int", 128, 128, false},
		{"float64", float64(0), 0, false},
		{"string invalid", "abc", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAlterID(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestBase64Decode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"standard", "aGVsbG8=", "hello", false},
		{"url-safe dashes", "aGVsbG8", "hello", false},
		{"url-safe underscores", "aGVsbG8", "hello", false},
		{"with whitespace", "  aGVsbG8=  ", "hello", false},
		{"url-safe chars", "PD9waHA-", "<?php>", false},
		{"empty", "", "", false},
		{"invalid", "!!!", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := base64Decode(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got %s", string(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", string(got), tc.want)
			}
		})
	}
}

func TestParseAuth(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantUser string
		wantPass string
	}{
		{"plain user:pass", "user:pass", "user", "pass"},
		{"plain user only (not base64)", "user!", "user!", ""},
		{"plain with colon", "a:b", "a", "b"},
		{"base64 user:pass", "dXNlcjpwYXNz", "user", "pass"},
		{"empty", "", "", ""},
		{"url-encoded", "user%40host:p%40ss", "user@host", "p@ss"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user, pass := parseAuth(tc.input)
			if user != tc.wantUser || pass != tc.wantPass {
				t.Errorf("got (%q, %q), want (%q, %q)", user, pass, tc.wantUser, tc.wantPass)
			}
		})
	}
}

func TestParseNetIPPrefixList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{"empty", "", 0, false},
		{"single ipv4", "192.168.1.1/32", 1, false},
		{"multiple", "192.168.1.1/32,fd00::1/128", 2, false},
		{"with spaces", "192.168.1.1/32, fd00::1/128", 2, false},
		{"invalid", "not-a-prefix", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNetIPPrefixList(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("got %d prefixes, want %d", len(got), tc.want)
			}
		})
	}
}

func TestParseMultiplex(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var mux *option.OutboundMultiplexOptions
		params := url.Values{}
		parseMultiplex(params, &mux)
		if mux != nil {
			t.Errorf("expected nil mux, got %+v", mux)
		}
	})

	t.Run("enabled with streams", func(t *testing.T) {
		var mux *option.OutboundMultiplexOptions
		params := url.Values{}
		params.Set("mux", "8")
		parseMultiplex(params, &mux)
		if mux == nil || !mux.Enabled {
			t.Fatal("expected enabled mux")
		}
		if mux.MaxStreams != 8 {
			t.Errorf("got MaxStreams=%d, want 8", mux.MaxStreams)
		}
	})

	t.Run("enabled without streams", func(t *testing.T) {
		var mux *option.OutboundMultiplexOptions
		params := url.Values{}
		params.Set("mux", "1")
		parseMultiplex(params, &mux)
		if mux == nil || !mux.Enabled {
			t.Fatal("expected enabled mux")
		}
		if mux.MaxStreams != 0 {
			t.Errorf("got MaxStreams=%d, want 0", mux.MaxStreams)
		}
	})
}
