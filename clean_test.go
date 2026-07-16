package singproxy

import (
	"testing"
)

func TestCleanProxyURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "amp entity decode",
			input: "vless://uuid@host:443?a=1&amp;b=2",
			want:  "vless://uuid@host:443?a=1&b=2",
		},
		{
			name:  "unicode amp decode",
			input: "vless://uuid@host:443?a=1\u0026b=2",
			want:  "vless://uuid@host:443?a=1&b=2",
		},
		{
			name:  "strip remarks param",
			input: "vless://uuid@host:443?sni=foo&remarks=bar",
			want:  "vless://uuid@host:443?sni=foo",
		},
		{
			name:  "strip tag param",
			input: "vless://uuid@host:443?sni=foo&tag=bar",
			want:  "vless://uuid@host:443?sni=foo",
		},
		{
			name:  "strip label param",
			input: "vless://uuid@host:443?sni=foo&label=bar",
			want:  "vless://uuid@host:443?sni=foo",
		},
		{
			name:  "strip ps param",
			input: "vless://uuid@host:443?sni=foo&ps=bar",
			want:  "vless://uuid@host:443?sni=foo",
		},
		{
			name:  "fragment stripped",
			input: "vless://uuid@host:443?sni=foo#remark",
			want:  "vless://uuid@host:443?sni=foo",
		},
		{
			name:  "no query params",
			input: "vless://uuid@host:443",
			want:  "vless://uuid@host:443",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cleanProxyURL(tc.input)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCleanBruteForce_Vmess(t *testing.T) {
	input := "vmess://eyJ2IjogIjIiLCAiYWRkIjogImguY29tIn0=#some remark"
	got := cleanBruteForce(input)
	want := "vmess://eyJ2IjogIjIiLCAiYWRkIjogImguY29tIn0=someremark"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCleanBruteForce_SS_MultipleAt(t *testing.T) {
	input := "ss://user@pass@host:8080@comment"
	got := cleanBruteForce(input)
	want := "ss://user@pass@host:8080"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCleanBruteForce_Trojan_Dashes(t *testing.T) {
	input := "trojan://pass-->with-->dashes@host:443"
	got := cleanBruteForce(input)
	want := "trojan://pass--with--dashes@host:443"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCleanBruteForce_Trojan_Spaces(t *testing.T) {
	input := "trojan://pass with spaces@host:443"
	got := cleanBruteForce(input)
	want := "trojan://pass%20with%20spaces@host:443"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCleanBruteForce_Vless_TripleDashes(t *testing.T) {
	input := "vless://uuid@host:443---garbage?security=tls"
	got := cleanBruteForce(input)
	want := "vless://uuid@host:443?security=tls"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCleanBruteForce_NoScheme(t *testing.T) {
	input := "just-a-string"
	got := cleanBruteForce(input)
	if got != input {
		t.Errorf("got %q, want %q", got, input)
	}
}
