package singproxy

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http2/hpack"
)

func xhttpBase64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

type xhttpPaddingMethod string

const (
	xhttpPaddingMethodRepeatX  xhttpPaddingMethod = "repeat-x"
	xhttpPaddingMethodTokenish xhttpPaddingMethod = "tokenish"
)

const xhttpCharsetBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

const xhttpAvgHuffmanBytesPerCharBase62 = 0.8

const xhttpValidationTolerance = 2

type xhttpPaddingPlacement struct {
	Placement string
	Key       string
	Header    string
	RawURL    string
}

type xhttpPaddingConfig struct {
	Length    int
	Placement xhttpPaddingPlacement
	Method    xhttpPaddingMethod
}

func xhttpRandStringFromCharset(n int, charset string) (string, bool) {
	if n <= 0 || len(charset) == 0 {
		return "", false
	}
	m := len(charset)
	limit := byte(256 - (256 % m))
	result := make([]byte, n)
	i := 0
	buf := make([]byte, 256)
	for i < n {
		if _, err := rand.Read(buf); err != nil {
			return "", false
		}
		for _, rb := range buf {
			if rb >= limit {
				continue
			}
			result[i] = charset[int(rb)%m]
			i++
			if i == n {
				break
			}
		}
	}
	return string(result), true
}

func xhttpAbsInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func xhttpGenerateTokenishPaddingBase62(targetHuffmanBytes int) string {
	n := int(math.Ceil(float64(targetHuffmanBytes) / xhttpAvgHuffmanBytesPerCharBase62))
	if n < 1 {
		n = 1
	}
	randBase62Str, ok := xhttpRandStringFromCharset(n, xhttpCharsetBase62)
	if !ok {
		return ""
	}
	const maxIter = 150
	adjustChar := byte('X')
	for iter := 0; iter < maxIter; iter++ {
		currentLength := int(hpack.HuffmanEncodeLength(randBase62Str))
		diff := currentLength - targetHuffmanBytes
		if xhttpAbsInt(diff) <= xhttpValidationTolerance {
			return randBase62Str
		}
		if diff < 0 {
			randBase62Str += string(adjustChar)
			if adjustChar == 'X' {
				adjustChar = 'Z'
			} else {
				adjustChar = 'X'
			}
		} else {
			if len(randBase62Str) <= 1 {
				return randBase62Str
			}
			randBase62Str = randBase62Str[:len(randBase62Str)-1]
		}
	}
	return randBase62Str
}

func xhttpGeneratePadding(method xhttpPaddingMethod, length int) string {
	if length <= 0 {
		return ""
	}
	switch method {
	case xhttpPaddingMethodRepeatX:
		return strings.Repeat("X", length)
	case xhttpPaddingMethodTokenish:
		paddingValue := xhttpGenerateTokenishPaddingBase62(length)
		if paddingValue == "" {
			return strings.Repeat("X", length)
		}
		return paddingValue
	default:
		return strings.Repeat("X", length)
	}
}

func (c *xhttpConfig) buildXPaddingConfig(reqURL string, length int) xhttpPaddingConfig {
	config := xhttpPaddingConfig{Length: length}
	if c.XPaddingObfsMode {
		config.Placement = xhttpPaddingPlacement{
			Placement: c.XPaddingPlacement,
			Key:       c.XPaddingKey,
			Header:    c.XPaddingHeader,
			RawURL:    reqURL,
		}
		config.Method = xhttpPaddingMethod(c.XPaddingMethod)
	} else {
		config.Placement = xhttpPaddingPlacement{
			Placement: xhttpPlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    reqURL,
		}
	}
	return config
}

func (c *xhttpConfig) applyXPaddingToHeader(h http.Header, config xhttpPaddingConfig) {
	if h == nil {
		return
	}
	paddingValue := xhttpGeneratePadding(config.Method, config.Length)
	switch p := config.Placement; p.Placement {
	case xhttpPlacementHeader:
		h.Set(p.Header, paddingValue)
	case xhttpPlacementQueryInHeader:
		u, err := url.Parse(p.RawURL)
		if err != nil || u == nil {
			return
		}
		u.RawQuery = p.Key + "=" + paddingValue
		h.Set(p.Header, u.String())
	}
}

func (c *xhttpConfig) applyXPaddingToRequest(reqHeaders http.Header, reqURL *url.URL, config xhttpPaddingConfig) {
	placement := config.Placement.Placement
	if placement == xhttpPlacementHeader || placement == xhttpPlacementQueryInHeader {
		c.applyXPaddingToHeader(reqHeaders, config)
		return
	}
	paddingValue := xhttpGeneratePadding(config.Method, config.Length)
	if placement == xhttpPlacementQuery {
		q := reqURL.Query()
		q.Set(config.Placement.Key, paddingValue)
		reqURL.RawQuery = q.Encode()
	}
}

func (c *xhttpConfig) fillStreamRequestHeaders(reqHeaders http.Header, reqURL *url.URL, sessionID string, hasBody bool) error {
	c.applyMasqueradedHeaders(reqHeaders, "fetch")

	xPaddingBytes, err := c.GetNormalizedXPaddingBytes()
	if err != nil {
		return err
	}
	c.applyXPaddingToRequest(reqHeaders, reqURL, c.buildXPaddingConfig(reqURL.String(), xPaddingBytes.Rand()))
	c.applyMetaToRequest(reqHeaders, reqURL, sessionID, "")

	if hasBody && !c.NoGRPCHeader {
		reqHeaders.Set("Content-Type", "application/grpc")
	}

	return nil
}

func (c *xhttpConfig) fillDownloadRequestHeaders(reqHeaders http.Header, reqURL *url.URL, sessionID string) error {
	return c.fillStreamRequestHeaders(reqHeaders, reqURL, sessionID, false)
}

func (c *xhttpConfig) fillPacketRequestHeaders(reqHeaders http.Header, reqURL *url.URL, sessionId string, seqStr string, data []byte) error {
	dataPlacement := c.GetNormalizedUplinkDataPlacement()

	if dataPlacement == xhttpPlacementBody || dataPlacement == xhttpPlacementAuto {
		c.applyMasqueradedHeaders(reqHeaders, "fetch")
	} else {
		c.applyMasqueradedHeaders(reqHeaders, "fetch")
		if dataPlacement == xhttpPlacementHeader {
			uplinkChunkSize, err := c.GetNormalizedUplinkChunkSize()
			if err != nil {
				return err
			}
			key := c.UplinkDataKey
			encodedData := xhttpBase64URLEncode(data)
			for i := 0; len(encodedData) > 0; i++ {
				chunkSize := uplinkChunkSize.Rand()
				if len(encodedData) < chunkSize {
					chunkSize = len(encodedData)
				}
				reqHeaders.Set(fmt.Sprintf("%s-%d", key, i), encodedData[:chunkSize])
				encodedData = encodedData[chunkSize:]
			}
		}
	}

	xPaddingBytes, err := c.GetNormalizedXPaddingBytes()
	if err != nil {
		return err
	}
	c.applyXPaddingToRequest(reqHeaders, reqURL, c.buildXPaddingConfig(reqURL.String(), xPaddingBytes.Rand()))
	c.applyMetaToRequest(reqHeaders, reqURL, sessionId, seqStr)

	return nil
}

func (c *xhttpConfig) applyMetaToRequest(reqHeaders http.Header, reqURL *url.URL, sessionId string, seqStr string) {
	sessionPlacement := c.GetNormalizedSessionPlacement()
	seqPlacement := c.GetNormalizedSeqPlacement()
	sessionKey := c.GetNormalizedSessionKey()
	seqKey := c.GetNormalizedSeqKey()

	if sessionId != "" {
		switch sessionPlacement {
		case xhttpPlacementPath:
			reqURL.Path = xhttpAppendToPath(reqURL.Path, sessionId)
		case xhttpPlacementQuery:
			q := reqURL.Query()
			q.Set(sessionKey, sessionId)
			reqURL.RawQuery = q.Encode()
		case xhttpPlacementHeader:
			reqHeaders.Set(sessionKey, sessionId)
		}
	}

	if seqStr != "" {
		switch seqPlacement {
		case xhttpPlacementPath:
			reqURL.Path = xhttpAppendToPath(reqURL.Path, seqStr)
		case xhttpPlacementQuery:
			q := reqURL.Query()
			q.Set(seqKey, seqStr)
			reqURL.RawQuery = q.Encode()
		case xhttpPlacementHeader:
			reqHeaders.Set(seqKey, seqStr)
		}
	}
}
