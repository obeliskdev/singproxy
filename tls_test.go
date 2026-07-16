package singproxy

import (
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseTLS_None(t *testing.T) {
	container := &option.OutboundTLSOptionsContainer{}
	params := url.Values{}
	parseTLS(params, container, "fallback.example.com")
	if container.TLS != nil {
		t.Errorf("expected nil TLS for security=none, got %+v", container.TLS)
	}
}

func TestParseTLS_TLS(t *testing.T) {
	container := &option.OutboundTLSOptionsContainer{}
	params := url.Values{}
	params.Set("security", "tls")
	params.Set("sni", "sni.example.com")
	params.Set("alpn", "h2,http/1.1")
	params.Set("fp", "chrome")
	params.Set("insecure", "1")
	parseTLS(params, container, "fallback.example.com")

	if container.TLS == nil || !container.TLS.Enabled {
		t.Fatal("expected enabled TLS")
	}
	if container.TLS.ServerName != "sni.example.com" {
		t.Errorf("SNI: got %q, want sni.example.com", container.TLS.ServerName)
	}
	if !container.TLS.Insecure {
		t.Errorf("expected insecure=true")
	}
	if len(container.TLS.ALPN) != 2 || container.TLS.ALPN[0] != "h2" {
		t.Errorf("ALPN: got %v, want [h2 http/1.1]", container.TLS.ALPN)
	}
	if container.TLS.UTLS == nil || container.TLS.UTLS.Fingerprint != "chrome" {
		t.Errorf("UTLS fingerprint: got %+v, want chrome", container.TLS.UTLS)
	}
}

func TestParseTLS_AllowInsecureAlias(t *testing.T) {
	container := &option.OutboundTLSOptionsContainer{}
	params := url.Values{}
	params.Set("security", "tls")
	params.Set("allowInsecure", "1")
	parseTLS(params, container, "fallback.example.com")
	if !container.TLS.Insecure {
		t.Errorf("allowInsecure=1 should set Insecure=true")
	}
}

func TestParseTLS_AllowInsecureUnderscore(t *testing.T) {
	container := &option.OutboundTLSOptionsContainer{}
	params := url.Values{}
	params.Set("security", "tls")
	params.Set("allow_insecure", "1")
	parseTLS(params, container, "fallback.example.com")
	if !container.TLS.Insecure {
		t.Errorf("allow_insecure=1 should set Insecure=true")
	}
}

func TestParseTLS_FallbackSNI(t *testing.T) {
	container := &option.OutboundTLSOptionsContainer{}
	params := url.Values{}
	params.Set("security", "tls")
	parseTLS(params, container, "fallback.example.com")
	if container.TLS.ServerName != "fallback.example.com" {
		t.Errorf("SNI fallback: got %q, want fallback.example.com", container.TLS.ServerName)
	}
}

func TestParseTLS_HostAsSNI(t *testing.T) {
	container := &option.OutboundTLSOptionsContainer{}
	params := url.Values{}
	params.Set("security", "tls")
	params.Set("host", "host.example.com")
	parseTLS(params, container, "fallback.example.com")
	if container.TLS.ServerName != "host.example.com" {
		t.Errorf("SNI from host: got %q, want host.example.com", container.TLS.ServerName)
	}
}

func TestParseTLS_Reality(t *testing.T) {
	container := &option.OutboundTLSOptionsContainer{}
	params := url.Values{}
	params.Set("security", "reality")
	params.Set("pbk", "publickey123")
	params.Set("sid", "shortid456")
	params.Set("fp", "firefox")
	parseTLS(params, container, "fallback.example.com")

	if container.TLS == nil || !container.TLS.Enabled {
		t.Fatal("expected enabled TLS")
	}
	if container.TLS.Reality == nil || !container.TLS.Reality.Enabled {
		t.Fatal("expected enabled Reality")
	}
	if container.TLS.Reality.PublicKey != "publickey123" {
		t.Errorf("Reality PublicKey: got %q, want publickey123", container.TLS.Reality.PublicKey)
	}
	if container.TLS.Reality.ShortID != "shortid456" {
		t.Errorf("Reality ShortID: got %q, want shortid456", container.TLS.Reality.ShortID)
	}
	if container.TLS.Insecure {
		t.Errorf("Reality should set Insecure=false")
	}
	if container.TLS.UTLS == nil || container.TLS.UTLS.Fingerprint != "firefox" {
		t.Errorf("UTLS fingerprint: got %+v, want firefox", container.TLS.UTLS)
	}
}

func TestParseTLS_RealityDefaultFingerprint(t *testing.T) {
	container := &option.OutboundTLSOptionsContainer{}
	params := url.Values{}
	params.Set("security", "reality")
	params.Set("pbk", "key")
	params.Set("sid", "sid")
	parseTLS(params, container, "host.com")
	if container.TLS.UTLS.Fingerprint != "chrome" {
		t.Errorf("default fingerprint: got %q, want chrome", container.TLS.UTLS.Fingerprint)
	}
}

func TestParseTLS_RealityNoPublicKey(t *testing.T) {
	container := &option.OutboundTLSOptionsContainer{}
	params := url.Values{}
	params.Set("security", "reality")
	params.Set("sid", "sid")
	parseTLS(params, container, "host.com")
	if container.TLS != nil {
		t.Errorf("expected nil TLS when pbk missing, got %+v", container.TLS)
	}
}

func TestParseTLS_RealityShortIDWithAt(t *testing.T) {
	container := &option.OutboundTLSOptionsContainer{}
	params := url.Values{}
	params.Set("security", "reality")
	params.Set("pbk", "key")
	params.Set("sid", "shortid@extra")
	parseTLS(params, container, "host.com")
	if container.TLS.Reality.ShortID != "shortid" {
		t.Errorf("ShortID with @: got %q, want shortid", container.TLS.Reality.ShortID)
	}
}

func TestParseTLS_PreExistingTLS(t *testing.T) {
	container := &option.OutboundTLSOptionsContainer{
		TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "preexisting.com"},
	}
	params := url.Values{}
	parseTLS(params, container, "fallback.example.com")
	if container.TLS == nil {
		t.Fatal("pre-existing TLS should be preserved")
	}
	if !container.TLS.Enabled {
		t.Errorf("pre-existing Enabled should be preserved")
	}
}

func TestNormalizeTrojanGoParams(t *testing.T) {
	t.Run("ssl_sni to sni", func(t *testing.T) {
		params := url.Values{}
		params.Set("ssl_sni", "ssl-sni.example.com")
		normalizeTrojanGoParams(params)
		if params.Get("sni") != "ssl-sni.example.com" {
			t.Errorf("sni: got %q, want ssl-sni.example.com", params.Get("sni"))
		}
	})

	t.Run("ssl_sni does not override sni", func(t *testing.T) {
		params := url.Values{}
		params.Set("sni", "original.com")
		params.Set("ssl_sni", "ssl-sni.example.com")
		normalizeTrojanGoParams(params)
		if params.Get("sni") != "original.com" {
			t.Errorf("sni: got %q, want original.com", params.Get("sni"))
		}
	})

	t.Run("ssl_verify false sets insecure", func(t *testing.T) {
		params := url.Values{}
		params.Set("ssl_verify", "false")
		normalizeTrojanGoParams(params)
		if params.Get("insecure") != "1" {
			t.Errorf("insecure: got %q, want 1", params.Get("insecure"))
		}
	})

	t.Run("ssl_verify true does not set insecure", func(t *testing.T) {
		params := url.Values{}
		params.Set("ssl_verify", "true")
		normalizeTrojanGoParams(params)
		if params.Get("insecure") != "" {
			t.Errorf("insecure: got %q, want empty", params.Get("insecure"))
		}
	})

	t.Run("no ssl params leaves everything alone", func(t *testing.T) {
		params := url.Values{}
		params.Set("sni", "keep.com")
		normalizeTrojanGoParams(params)
		if params.Get("sni") != "keep.com" {
			t.Errorf("sni: got %q, want keep.com", params.Get("sni"))
		}
	})
}
