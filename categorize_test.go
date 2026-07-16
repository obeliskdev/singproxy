package singproxy

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestCategorizeErrors(t *testing.T) {
	path := os.Getenv("SINGPROXY_TEST_LIST")
	if path == "" {
		t.Skip("Set SINGPROXY_TEST_LIST")
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(string(body), "\n")
	var proxyURLs []string
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			proxyURLs = append(proxyURLs, trimmed)
		}
	}

	_, errs := FromURLs(Config{DialTimeout: 8 * time.Second}, proxyURLs...)

	categories := map[string]int{}
	examples := map[string]string{}
	for _, e := range errs {
		msg := e.Error()
		scheme := "unknown"
		if strings.Contains(msg, "(ss://") || strings.HasPrefix(msg, "parsing ss") {
			scheme = "ss"
		} else if strings.HasPrefix(msg, "parsing vmess") || strings.Contains(msg, "(vmess://") {
			scheme = "vmess"
		} else if strings.HasPrefix(msg, "parsing vless") || strings.Contains(msg, "(vless://") {
			scheme = "vless"
		} else if strings.HasPrefix(msg, "parsing trojan") || strings.Contains(msg, "(trojan://") {
			scheme = "trojan"
		} else if strings.Contains(msg, "failed to parse proxy") {
			scheme = "url_parse"
		}

		// Categorize by error type
		cat := scheme + ": "
		switch {
		case strings.Contains(msg, "missing port in address") || strings.Contains(msg, "host/port invalid"):
			cat += "host/port"
		case strings.Contains(msg, "missing password"):
			cat += "missing_password"
		case strings.Contains(msg, "cannot unmarshal"):
			cat += "json_unmarshal"
		case strings.Contains(msg, "missing ']' in host"):
			cat += "malformed_url"
		case strings.Contains(msg, "unsupported vless encryption"):
			cat += "unsupported_encryption"
		case strings.Contains(msg, "invalid transport"):
			cat += "invalid_transport"
		case strings.Contains(msg, "invalid ss base64"):
			cat += "ss_base64"
		case strings.Contains(msg, "unknown scheme"):
			cat += "unknown_scheme"
		case strings.Contains(msg, "create") && strings.Contains(msg, "outbound failed"):
			cat += "outbound_create"
		default:
			cat += "other"
		}

		categories[cat]++
		if _, ok := examples[cat]; !ok {
			examples[cat] = msg
		}
	}

	t.Logf("Total errors: %d out of %d proxies", len(errs), len(proxyURLs))
	for cat, count := range categories {
		t.Logf("  %3d  %s", count, cat)
	}
	for cat, ex := range examples {
		t.Logf("  EXAMPLE [%s]: %s", cat, truncate(ex, 300))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
