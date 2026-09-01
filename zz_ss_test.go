package singproxy

import (
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestSS2022KeyWithColonPreserved(t *testing.T) {
	// ss2022 userinfo is "method:serverKey:userKey"; the password must
	// keep its colons instead of being truncated at the first one.
	const b64 = "MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206c2VydmVyS2V5OnVzZXJLZXk="
	u, _ := url.Parse("ss://" + b64 + "@1.2.3.4:8388")
	out := &option.ShadowsocksOutboundOptions{}
	if err := parseShadowsocks(out, u); err != nil {
		t.Fatal(err)
	}
	if out.Password != "serverKey:userKey" {
		t.Errorf("password truncated: got %q, want %q", out.Password, "serverKey:userKey")
	}
}
