package singproxy

import (
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/option"
)

func parseTLS(params url.Values, tls *option.OutboundTLSOptionsContainer, fallbackSNI string) {
	security := strings.ToLower(params.Get("security"))
	if (security == "none" || security == "") && tls.TLS == nil {
		return
	}
	if tls.TLS == nil {
		tls.TLS = new(option.OutboundTLSOptions)
	}
	tls.TLS.Enabled = true
	sni := params.Get("sni")
	if sni == "" {
		sni = params.Get("host")
	}
	if sni == "" {
		sni = fallbackSNI
	}
	tls.TLS.ServerName = sni
	if security == "reality" {
		pbk := params.Get("pbk")
		if pbk == "" {
			tls.TLS = nil
			return
		}
		sid := params.Get("sid")
		if idx := strings.IndexAny(sid, "@"); idx != -1 {
			sid = sid[:idx]
		}
		tls.TLS.Insecure = false
		tls.TLS.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: pbk,
			ShortID:   sid,
		}
		if tls.TLS.UTLS == nil {
			tls.TLS.UTLS = new(option.OutboundUTLSOptions)
		}
		tls.TLS.UTLS.Enabled = true
		if fp := params.Get("fp"); fp != "" {
			tls.TLS.UTLS.Fingerprint = fp
		} else {
			tls.TLS.UTLS.Fingerprint = "chrome"
		}
	} else {
		tls.TLS.Insecure = parseBool(params.Get("allowInsecure")) || parseBool(params.Get("insecure")) || parseBool(params.Get("allow_insecure"))
	}
	if alpn := params.Get("alpn"); alpn != "" {
		tls.TLS.ALPN = strings.Split(alpn, ",")
	}
	if fp := params.Get("fp"); fp != "" {
		if tls.TLS.UTLS == nil {
			tls.TLS.UTLS = new(option.OutboundUTLSOptions)
		}
		tls.TLS.UTLS.Enabled = true
		tls.TLS.UTLS.Fingerprint = fp
	}
}

func normalizeTrojanGoParams(params url.Values) {
	if sslSNI := params.Get("ssl_sni"); sslSNI != "" && params.Get("sni") == "" {
		params.Set("sni", sslSNI)
	}
	if sslVerify := params.Get("ssl_verify"); sslVerify != "" {
		if !parseBool(sslVerify) {
			params.Set("insecure", "1")
		}
	}
}
