package singproxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const proxyListURL = "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed"

func TestParseRealWorldProxies(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live network test in short mode")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(proxyListURL)
	if err != nil {
		t.Fatalf("Failed to fetch proxy list from %s: %v", proxyListURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to fetch proxy list: received status code %d", resp.StatusCode)
	}

	b64Body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	decodedBody, err := base64.StdEncoding.DecodeString(string(b64Body))
	if err != nil {
		t.Fatalf("Failed to decode base64 content from URL: %v", err)
	}

	lines := strings.Split(string(decodedBody), "\n")
	var proxyURLs []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			proxyURLs = append(proxyURLs, line)
		}
	}

	if len(proxyURLs) == 0 {
		t.Fatal("Decoded proxy list is empty, cannot proceed with test.")
	}

	t.Logf("Attempting to parse %d real-world proxy URLs...", len(proxyURLs))

	proxies, errs := FromURLs(time.Second*8, proxyURLs...)

	if len(errs) > 0 {
		t.Errorf("Encountered %d errors while parsing %d proxies:", len(errs), len(proxyURLs))
		for i, e := range errs {
			t.Errorf("  - Error %d: %v", i+1, e)
		}
	}

	if len(proxies) != len(proxyURLs) {
		t.Errorf("Mismatch in count: expected to parse %d proxies, but only got %d", len(proxyURLs), len(proxies))
	}

	t.Logf("Successfully parsed %d out of %d proxies.", len(proxies), len(proxyURLs))

	if len(errs) > 0 {
		t.Fail()
	}
}
