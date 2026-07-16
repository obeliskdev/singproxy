package singproxy

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseRealWorldProxies(t *testing.T) {
	path := os.Getenv("SINGPROXY_TEST_LIST")
	if path == "" {
		t.Skip("Set SINGPROXY_TEST_LIST to a proxy list file to run this test")
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read proxy list from %s: %v", path, err)
	}

	lines := strings.Split(string(body), "\n")
	var proxyURLs []string
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			proxyURLs = append(proxyURLs, trimmed)
		}
	}

	if len(proxyURLs) == 0 {
		t.Fatal("Proxy list is empty, cannot proceed with test.")
	}

	t.Logf("Attempting to parse %d real-world proxy URLs...", len(proxyURLs))

	proxies, errs := FromURLs(time.Second*8, proxyURLs...)

	t.Logf("Successfully parsed %d out of %d proxies (%d errors).", len(proxies), len(proxyURLs), len(errs))

	errorByType := map[string]int{}
	for _, e := range errs {
		msg := e.Error()
		if idx := strings.Index(msg, ":"); idx > 0 {
			msg = msg[:idx]
		}
		errorByType[msg]++
	}
	for msg, count := range errorByType {
		t.Logf("  error category (%d): %s", count, msg)
	}

	if len(errs) > 0 {
		t.Logf("First 10 errors:")
		max := 10
		if len(errs) < max {
			max = len(errs)
		}
		for i := 0; i < max; i++ {
			t.Logf("  [%d] %v", i, errs[i])
		}
	}
}
