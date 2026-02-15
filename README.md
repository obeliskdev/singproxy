# Sing-Proxy: A Robust Go Proxy Client Library

[![Go Report Card](https://goreportcard.com/badge/github.com/obeliskdev/singproxy)](https://goreportcard.com/report/github.com/obeliskdev/singproxy)

Sing-Proxy is a high-level Go library designed to simplify connecting through various proxy protocols. Built as a
wrapper around the powerful `sagernet/sing-box` core, its primary feature is its exceptional ability to parse and handle
a vast number of non-standard, malformed, and "dirty" proxy URLs found in the wild.

If you need to consume proxy lists from public Telegram channels, subscription services, or other non-standard sources,
Sing-Proxy is built to handle the mess for you.

## Features

- **Unified `Proxy` Interface**: A single, simple API for Shadowsocks, VLESS, VMess, Trojan, and more.
- **Powered by `sing-box`**: Leverages the robust, performant, and up-to-date networking core of `sing-box`.
- **Resilient URL Parsing**: Intelligently cleans and fixes common errors in proxy URLs *before* parsing, dramatically
  increasing success rates with public proxy lists.
- **Wide Protocol Support**:
    - VLESS (with REALITY, gRPC, WebSocket, HTTP Upgrade)
    - VMess
    - Trojan
    - Shadowsocks (including `encryption=none` variants and SIP003 formats)
    - Hysteria/Hysteria2
    - WireGuard
    - SOCKS5/SOCKS4
    - HTTP/HTTPS/HTTP2
    - TUIC
    - SSH
    - AnyTLS
    - NaiveProxy
    - ShadowTLS
- **Concurrency-Ready**: Includes a `FromURLs` helper to parse large lists of proxies in parallel.

## Installation

```sh
go get github.com/obeliskdev/singproxy
```

Use following tags for building you binary

```
-tags=with_utls,with_gvisor,with_quic,with_dhcp,with_acme,with_clash_api,with_wireguard
```

## Basic Usage

The library exposes a straightforward API. You provide a proxy URL, and you get back an object that satisfies the
`Proxy` interface, which has a `DialContext` method you can use in any standard Go networking code.

```go
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/obeliskdev/singproxy"
)

func main() {
	// Example VLESS URL with a REALITY configuration and a name in the fragment.
	proxyURL := "vless://a-uuid@example.com:443?security=reality&sni=sni.example.com&fp=chrome&pbk=YOUR_REALITY_KEY&sid=abcdef1234#MyVlessProxy"
	timeout := 8 * time.Second

	// 1. Parse the URL using the factory function.
	proxy, err := singproxy.FromURL(timeout, proxyURL)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse proxy URL: %v", err))
	}

	// The String() method returns the cleaned name from the URL fragment.
	fmt.Printf("Successfully parsed proxy: %s\n", proxy.String()) // Prints "vless://a-uuid@example.com:443?security=reality&sni=sni.example.com&fp=chrome&pbk=YOUR_REALITY_KEY&sid=abcdef1234"

	// 2. Create an HTTP client that uses the proxy's custom dialer.
	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				tcpAddr, err := net.ResolveTCPAddr(network, addr)
				if err != nil {
					return nil, err
				}
				// Use the proxy's DialContext method to establish the connection.
				return proxy.DialContext(ctx, network, tcpAddr)
			},
		},
	}

	// 3. Make a request to a test endpoint through the proxy.
	fmt.Println("Making request to httpbin.org/get...")
	resp, err := httpClient.Get("https://httpbin.org/get")
	if err != nil {
		panic(fmt.Sprintf("Request failed through proxy: %v", err))
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Response Body (first 100 bytes): %.100s...\n", string(body))
}
```

## Example: A Simple Concurrent Proxy Tester

This complete example demonstrates how to parse multiple URLs at once and test their connectivity concurrently.

```go
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/obeliskdev/singproxy"
)

// TestResult holds the outcome of a single proxy test.
type TestResult struct {
	ProxyName string
	Latency   time.Duration
	Success   bool
	Error     error
}

func main() {
	proxyURLs := []string{
		"direct", // A direct connection for baseline comparison.
		"vless://a-uuid@example.com:443?security=tls&sni=example.com#VLESS-Example",
		"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8080#Shadowsocks-Example",
		"trojan://password@example.com:443?sni=example.com#Trojan-Example",
		"this-is-an-invalid-url", // An invalid URL to show error handling.
		"hysteria2://-->invalid-user@example.com:4567#Malformed-Hysteria2", // Will be cleaned and parsed.
	}

	fmt.Printf("Parsing %d proxy URLs...\n", len(proxyURLs))
	timeout := 8 * time.Second

	// Use FromURLs to parse all proxies concurrently. It returns valid proxies and any errors.
	proxies, errs := singproxy.FromURLs(timeout, proxyURLs...)

	// Print any parsing errors encountered.
	if len(errs) > 0 {
		fmt.Printf("\nEncountered %d parsing errors:\n", len(errs))
		for _, err := range errs {
			fmt.Printf(" - %v\n", err)
		}
	}

	fmt.Printf("\nSuccessfully parsed %d proxies. Starting connection tests...\n\n", len(proxies))

	var wg sync.WaitGroup
	results := make(chan TestResult, len(proxies))

	// Test each valid proxy in its own goroutine.
	for _, p := range proxies {
		wg.Add(1)
		go testProxy(p, results, &wg)
	}

	// Wait for all tests to complete.
	wg.Wait()
	close(results)

	// Print the collected results.
	for result := range results {
		if result.Success {
			fmt.Printf("[SUCCESS] Proxy: %-30s | Latency: %s\n", result.ProxyName, result.Latency)
		} else {
			fmt.Printf("[FAILURE] Proxy: %-30s | Error: %v\n", result.ProxyName, result.Error)
		}
	}
}

// testProxy attempts to make an HTTP GET request through the given proxy and sends the result to a channel.
func testProxy(p singproxy.Proxy, results chan<- TestResult, wg *sync.WaitGroup) {
	defer wg.Done()

	result := TestResult{ProxyName: p.String()}
	startTime := time.Now()

	httpClient := &http.Client{
		Timeout: 10 * time.Second, // Timeout for the entire HTTP request.
		Transport: &http.Transport{
			// Use the proxy's custom dialer.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				tcpAddr, err := net.ResolveTCPAddr(network, addr)
				if err != nil {
					return nil, err
				}
				return p.DialContext(ctx, network, tcpAddr)
			},
			// Disable keep-alives for more accurate, isolated latency measurement.
			DisableKeepAlives: true,
		},
	}

	// Make the test request.
	resp, err := httpClient.Get("https://httpbin.org/get")
	if err != nil {
		result.Success = false
		result.Error = err
		results <- result
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		result.Success = true
		result.Latency = time.Since(startTime)
		// Drain the body to properly measure the time for the full response.
		_, _ = io.Copy(io.Discard, resp.Body)
	} else {
		result.Success = false
		result.Error = fmt.Errorf("bad status: %s", resp.Status)
	}

	results <- result
}
```

## How The Robust Parsing Works

Many proxy providers and aggregators generate URLs that don't strictly adhere to RFC standards. They often contain extra
metadata, comments, or invalid characters that cause standard Go parsers like `net/url.Parse` to fail.

Sing-Proxy addresses this with a multi-layered cleaning process in its `FromURL` function:

1. **Isolate Name**: The URL fragment (`#...`) is immediately separated to preserve the proxy's intended name.
2. **General Cleaning**: Removes common junk query parameters like `ps`, `remarks`, `tag`, etc.
3. **Protocol-Specific Cleaning**: Before parsing, it applies a set of "brute-force" rules tailored to each protocol's
   common mistakes:
    * **VMess**: Strips all non-Base64 characters from the payload.
    * **Hysteria2/Trojan**: Escapes invalid characters found in `userinfo` (like `-->`, `^`, `🤠`).
    * **Shadowsocks**: Corrects malformed structures like `ss://user@host:port@comment`.
    * **VLESS**: Cleans junk data appended to hostnames (e.g., `...:port---Telegram---`).
4. **Standard Parsing**: Only after these cleaning steps is the URL passed to Go's standard parser.
5. **Post-Parsing Fallbacks**: Within the individual protocol parsers, it applies fallbacks for common logical errors,
   such as using a default cipher when a Shadowsocks method is missing or handling non-standard transport names like
   `xhttp`.

## Supported Protocols

The library supports the following URL schemes:

- **VMess** (`vless://`)
- **HTTP** / **HTTPS** / **HTTP2** (`http://`, `https://`, `http2://`)
- **VLESS** (`vless://`)
- **Trojan** (`trojan://`, `trojan-go://`)
- **Shadowsocks** (`ss://`)
- **TUIC** (`tuic://`)
- **Hysteria** (`hysteria://`)
- **Hysteria2** (`hysteria2://`)
- **SSH** (`ssh://`)
- **SOCKS5** / **SOCKS4** (`socks5://`, `socks4://`)
- **WireGuard** (`wireguard://`)
- **Direct** (`direct`)
- **Tor** (`tor://`)
- **AnyTLS** (`anytls://`, `atls://`)
- **ShadowTLS** (`shadowtls://`)
- **NaiveProxy** (`naive://`, `naive+https://`)

## License

This project is licensed under the MIT License.

## Credits

- [sing-box](https://github.com/SagerNet/sing-box) core library
- [TGParse](https://github.com/Surfboardv2ray/TGParse) used proxies for test propose
