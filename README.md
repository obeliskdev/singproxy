# singproxy

`singproxy` is a Go proxy client library built on top of the `sagernet/sing-box` stack.

Its main goal is robust real-world URL handling. It can parse and normalize many malformed proxy URLs before creating usable dialers.

## What It Solves

Public proxy lists frequently include invalid or noisy URLs:
- bad escaping in credentials,
- mixed delimiters,
- extra metadata parameters,
- protocol-specific formatting mistakes.

`singproxy` cleans these inputs and converts them into a unified `Proxy` interface you can use with normal Go networking code.

## Installation

```bash
go get github.com/obeliskdev/singproxy
```

If your build requires optional sing-box capabilities, include relevant build tags, for example:

```bash
go build -tags "with_utls with_gvisor with_quic with_dhcp with_acme with_clash_api with_wireguard" ./...
```

## Proxy Interface

Every parsed proxy implements:

```go
type Proxy interface {
	String() string
	Addr() net.IP
	DialContext(ctx context.Context, network string, addr string) (net.Conn, error)
	DialContextAddr(ctx context.Context, network string, addr *net.TCPAddr) (net.Conn, error)
}
```

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/obeliskdev/singproxy"
)

func main() {
	proxy, err := singproxy.FromURL(
		8*time.Second,
		"vless://uuid@example.com:443?security=tls&sni=example.com#edge",
	)
	if err != nil {
		panic(err)
	}

	target := &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	conn, err := proxy.DialContextAddr(context.Background(), "tcp", target)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("connected through:", proxy.String())
}
```

## Parse Many URLs Concurrently

```go
urls := []string{
	"direct",
	"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8080#ss",
	"trojan://password@example.com:443?sni=example.com#tj",
	"not-a-valid-url",
}

proxies, errs := singproxy.FromURLs(8*time.Second, urls...)

fmt.Println("valid proxies:", len(proxies))
for _, e := range errs {
	fmt.Println("parse error:", e)
}
```

## Supported Schemes

- `direct`
- `vless://`
- `vmess://`
- `trojan://`, `trojan-go://`
- `ss://`
- `ssr://`, `shadowsocksr://`
- `hysteria://`, `hysteria2://`
- `tuic://`
- `ssh://`
- `socks://`, `socks5://`, `socks4://`, `socks4a://`
- `http://`, `https://`, `http2://`
- `wireguard://`
- `shadowtls://`
- `anytls://`, `atls://`
- `tor://`

> **Note:** `ssr://` and `shadowsocksr://` links are parsed, but sing-box 1.6+
> no longer supports creating ShadowsocksR outbounds at runtime; the parsed
> options will be rejected by sing-box's outbound factory with a
> "deprecated" error.

## HTTP Client Integration Example

```go
proxy, _ := singproxy.FromURL(8*time.Second, "direct")

client := &http.Client{
	Timeout: 12 * time.Second,
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			tcpAddr, err := net.ResolveTCPAddr(network, addr)
			if err != nil {
				return nil, err
			}
			return proxy.DialContextAddr(ctx, network, tcpAddr)
		},
	},
}
```

## Testing

```bash
# Fast: unit tests only (no build tags required)
go test ./...

# Full: includes sing-box integration tests
go test -tags "with_utls with_gvisor with_quic with_dhcp with_acme with_clash_api with_wireguard" -race ./...
```

To run the real-world proxy-list integration test, set `SINGPROXY_TEST_LIST` to a
file containing one proxy URL per line. The test is skipped otherwise.

## License

MIT. See `LICENSE`.

## Credits

- `sagernet/sing-box`
