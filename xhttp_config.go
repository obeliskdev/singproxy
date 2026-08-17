package singproxy

import (
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	xhttpPlacementQueryInHeader = "queryInHeader"
	xhttpPlacementCookie        = "cookie"
	xhttpPlacementHeader        = "header"
	xhttpPlacementQuery         = "query"
	xhttpPlacementPath          = "path"
	xhttpPlacementBody          = "body"
	xhttpPlacementAuto          = "auto"
)

type xhttpRange struct {
	Min int
	Max int
}

func (r xhttpRange) Rand() int {
	if r.Min == r.Max {
		return r.Min
	}
	return r.Min + rand.IntN(r.Max-r.Min+1)
}

func xhttpParseRange(s string, fallback string) (xhttpRange, error) {
	if strings.TrimSpace(s) == "" {
		return xhttpParseRangeValue(fallback)
	}
	return xhttpParseRangeValue(s)
}

func xhttpParseRangeValue(s string) (xhttpRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return xhttpRange{0, 0}, nil
	}
	parts := strings.Split(s, "-")
	if len(parts) == 1 {
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return xhttpRange{}, err
		}
		return xhttpRange{v, v}, nil
	}
	if len(parts) != 2 {
		return xhttpRange{}, fmt.Errorf("invalid range: %s", s)
	}
	minVal, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return xhttpRange{}, err
	}
	maxVal, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return xhttpRange{}, err
	}
	if minVal < 0 || maxVal < minVal {
		return xhttpRange{}, fmt.Errorf("invalid range: %s", s)
	}
	return xhttpRange{minVal, maxVal}, nil
}

type xhttpReuseConfig struct {
	MaxConcurrency   string
	MaxConnections   string
	CMaxReuseTimes   string
	HMaxRequestTimes string
	HMaxReusableSecs string
}

func (c *xhttpReuseConfig) resolveManagerConfig() (xhttpRange, xhttpRange, error) {
	if c == nil {
		return xhttpRange{}, xhttpRange{}, nil
	}
	maxConcurrency, err := xhttpParseRange(c.MaxConcurrency, "0")
	if err != nil {
		return xhttpRange{}, xhttpRange{}, fmt.Errorf("invalid max-concurrency: %w", err)
	}
	maxConnections, err := xhttpParseRange(c.MaxConnections, "0")
	if err != nil {
		return xhttpRange{}, xhttpRange{}, fmt.Errorf("invalid max-connections: %w", err)
	}
	return maxConcurrency, maxConnections, nil
}

func (c *xhttpReuseConfig) resolveEntryConfig() (xhttpRange, xhttpRange, xhttpRange, error) {
	if c == nil {
		return xhttpRange{}, xhttpRange{}, xhttpRange{}, nil
	}
	cMaxReuseTimes, err := xhttpParseRange(c.CMaxReuseTimes, "0")
	if err != nil {
		return xhttpRange{}, xhttpRange{}, xhttpRange{}, fmt.Errorf("invalid c-max-reuse-times: %w", err)
	}
	hMaxRequestTimes, err := xhttpParseRange(c.HMaxRequestTimes, "0")
	if err != nil {
		return xhttpRange{}, xhttpRange{}, xhttpRange{}, fmt.Errorf("invalid h-max-request-times: %w", err)
	}
	hMaxReusableSecs, err := xhttpParseRange(c.HMaxReusableSecs, "0")
	if err != nil {
		return xhttpRange{}, xhttpRange{}, xhttpRange{}, fmt.Errorf("invalid h-max-reusable-secs: %w", err)
	}
	return cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs, nil
}

type xhttpConfig struct {
	Host                 string
	Path                 string
	Mode                 string
	Headers              map[string]string
	NoGRPCHeader         bool
	XPaddingBytes        string
	XPaddingObfsMode     bool
	XPaddingKey          string
	XPaddingHeader       string
	XPaddingPlacement    string
	XPaddingMethod       string
	UplinkHTTPMethod     string
	SessionPlacement     string
	SessionKey           string
	SessionTable         string
	SessionLength        string
	SeqPlacement         string
	SeqKey               string
	UplinkDataPlacement  string
	UplinkDataKey        string
	UplinkChunkSize      string
	ScMaxEachPostBytes   string
	ScMinPostsIntervalMs string
	ReuseConfig          *xhttpReuseConfig
	DownloadConfig       *xhttpConfig

	TLSConfig *xhttpTLSConfig

	norm   atomic.Pointer[xhttpNormalized]
	masqMu sync.Mutex
	masq   xhttpMasqueradeCache
}

type xhttpNormalized struct {
	rawPath                 string
	rawUplinkHTTPMethod     string
	rawScMaxEachPostBytes   string
	rawScMinPostsIntervalMs string
	rawXPaddingBytes        string
	rawSessionPlacement     string
	rawSessionKey           string
	rawSeqPlacement         string
	rawSeqKey               string
	rawUplinkDataPlacement  string
	rawUplinkChunkSize      string
	path                    string
	uplinkHTTPMethod        string
	uplinkDataPlacement     string
	sessionPlacement        string
	sessionKey              string
	seqPlacement            string
	seqKey                  string
	scMaxEachPostBytes      xhttpRange
	scMinPostsIntervalMs    xhttpRange
	xPaddingBytes           xhttpRange
	uplinkChunkSize         xhttpRange
	scMaxEachPostBytesErr   error
	scMinPostsIntervalErr   error
	xPaddingBytesErr        error
	uplinkChunkSizeErr      error
}

func (n *xhttpNormalized) matches(c *xhttpConfig) bool {
	return n.rawPath == c.Path &&
		n.rawUplinkHTTPMethod == c.UplinkHTTPMethod &&
		n.rawScMaxEachPostBytes == c.ScMaxEachPostBytes &&
		n.rawScMinPostsIntervalMs == c.ScMinPostsIntervalMs &&
		n.rawXPaddingBytes == c.XPaddingBytes &&
		n.rawSessionPlacement == c.SessionPlacement &&
		n.rawSessionKey == c.SessionKey &&
		n.rawSeqPlacement == c.SeqPlacement &&
		n.rawSeqKey == c.SeqKey &&
		n.rawUplinkDataPlacement == c.UplinkDataPlacement &&
		n.rawUplinkChunkSize == c.UplinkChunkSize
}

func (c *xhttpConfig) normalized() *xhttpNormalized {
	if n := c.norm.Load(); n != nil && n.matches(c) {
		return n
	}
	n := &xhttpNormalized{
		rawPath:                 c.Path,
		rawUplinkHTTPMethod:     c.UplinkHTTPMethod,
		rawScMaxEachPostBytes:   c.ScMaxEachPostBytes,
		rawScMinPostsIntervalMs: c.ScMinPostsIntervalMs,
		rawXPaddingBytes:        c.XPaddingBytes,
		rawSessionPlacement:     c.SessionPlacement,
		rawSessionKey:           c.SessionKey,
		rawSeqPlacement:         c.SeqPlacement,
		rawSeqKey:               c.SeqKey,
		rawUplinkDataPlacement:  c.UplinkDataPlacement,
		rawUplinkChunkSize:      c.UplinkChunkSize,
	}
	n.path = c.computeNormalizedPath()
	n.uplinkHTTPMethod = c.computeUplinkHTTPMethod()
	n.uplinkDataPlacement = c.computeUplinkDataPlacement()
	n.sessionPlacement = c.computeSessionPlacement()
	n.sessionKey = c.computeSessionKey(n.sessionPlacement)
	n.seqPlacement = c.computeSeqPlacement()
	n.seqKey = c.computeSeqKey(n.seqPlacement)
	n.scMaxEachPostBytes, n.scMaxEachPostBytesErr = xhttpParseRange(c.ScMaxEachPostBytes, "1000000")
	if n.scMaxEachPostBytesErr == nil && n.scMaxEachPostBytes.Max == 0 {
		n.scMaxEachPostBytesErr = fmt.Errorf("invalid sc-max-each-post-bytes: must be greater than zero")
	}
	n.scMinPostsIntervalMs, n.scMinPostsIntervalErr = xhttpParseRange(c.ScMinPostsIntervalMs, "30")
	if n.scMinPostsIntervalErr == nil && n.scMinPostsIntervalMs.Max == 0 {
		n.scMinPostsIntervalErr = fmt.Errorf("invalid sc-min-posts-interval-ms: must be greater than zero")
	}
	n.xPaddingBytes, n.xPaddingBytesErr = xhttpParseRange(c.XPaddingBytes, "100-1000")
	n.uplinkChunkSize, n.uplinkChunkSizeErr = c.computeUplinkChunkSize(n.uplinkDataPlacement, n.scMaxEachPostBytes, n.scMaxEachPostBytesErr)
	c.norm.Store(n)
	return n
}

func (c *xhttpConfig) NormalizedMode() string {
	if c.Mode == "" {
		return "auto"
	}
	return c.Mode
}

func (c *xhttpConfig) EffectiveMode(hasReality bool) string {
	mode := c.NormalizedMode()
	if mode != "auto" {
		return mode
	}
	if hasReality {
		if c.DownloadConfig != nil {
			return "stream-up"
		}
		return "stream-one"
	}
	return "packet-up"
}

func (c *xhttpConfig) computeNormalizedPath() string {
	path := c.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return path
}

func (c *xhttpConfig) NormalizedPath() string {
	return c.normalized().path
}

func (c *xhttpConfig) computeUplinkHTTPMethod() string {
	if c.UplinkHTTPMethod == "" {
		return "POST"
	}
	return c.UplinkHTTPMethod
}

func (c *xhttpConfig) GetNormalizedUplinkHTTPMethod() string {
	return c.normalized().uplinkHTTPMethod
}

func (c *xhttpConfig) GetNormalizedScMaxEachPostBytes() (xhttpRange, error) {
	n := c.normalized()
	return n.scMaxEachPostBytes, n.scMaxEachPostBytesErr
}

func (c *xhttpConfig) GetNormalizedScMinPostsIntervalMs() (xhttpRange, error) {
	n := c.normalized()
	return n.scMinPostsIntervalMs, n.scMinPostsIntervalErr
}

func (c *xhttpConfig) GetNormalizedXPaddingBytes() (xhttpRange, error) {
	n := c.normalized()
	return n.xPaddingBytes, n.xPaddingBytesErr
}

func (c *xhttpConfig) computeSessionPlacement() string {
	if c.SessionPlacement == "" {
		return xhttpPlacementPath
	}
	return c.SessionPlacement
}

func (c *xhttpConfig) computeSeqPlacement() string {
	if c.SeqPlacement == "" {
		return xhttpPlacementPath
	}
	return c.SeqPlacement
}

func (c *xhttpConfig) computeUplinkDataPlacement() string {
	if c.UplinkDataPlacement == "" {
		return xhttpPlacementBody
	}
	return c.UplinkDataPlacement
}

func (c *xhttpConfig) computeSessionKey(placement string) string {
	if c.SessionKey != "" {
		return c.SessionKey
	}
	switch placement {
	case xhttpPlacementHeader:
		return "X-Session"
	case xhttpPlacementCookie, xhttpPlacementQuery:
		return "x_session"
	default:
		return ""
	}
}

func (c *xhttpConfig) computeSeqKey(placement string) string {
	if c.SeqKey != "" {
		return c.SeqKey
	}
	switch placement {
	case xhttpPlacementHeader:
		return "X-Seq"
	case xhttpPlacementCookie, xhttpPlacementQuery:
		return "x_seq"
	default:
		return ""
	}
}

func (c *xhttpConfig) GetNormalizedUplinkDataPlacement() string {
	return c.normalized().uplinkDataPlacement
}

func (c *xhttpConfig) GetNormalizedSessionPlacement() string {
	return c.normalized().sessionPlacement
}

func (c *xhttpConfig) GetNormalizedSeqPlacement() string {
	return c.normalized().seqPlacement
}

func (c *xhttpConfig) GetNormalizedSessionKey() string {
	return c.normalized().sessionKey
}

func (c *xhttpConfig) GetNormalizedSeqKey() string {
	return c.normalized().seqKey
}

func (c *xhttpConfig) computeUplinkChunkSize(placement string, scMax xhttpRange, scMaxErr error) (xhttpRange, error) {
	uplinkChunkSize, err := xhttpParseRange(c.UplinkChunkSize, "")
	if err != nil {
		return xhttpRange{}, fmt.Errorf("invalid uplink-chunk-size: %w", err)
	}
	if uplinkChunkSize.Max == 0 {
		switch placement {
		case xhttpPlacementCookie:
			return xhttpRange{Min: 2 * 1024, Max: 3 * 1024}, nil
		case xhttpPlacementHeader:
			return xhttpRange{Min: 3 * 1024, Max: 4 * 1024}, nil
		default:
			return scMax, scMaxErr
		}
	} else if uplinkChunkSize.Min < 64 {
		uplinkChunkSize.Min = 64
		if uplinkChunkSize.Max < 64 {
			uplinkChunkSize.Max = 64
		}
	}
	return uplinkChunkSize, nil
}

func (c *xhttpConfig) GetNormalizedUplinkChunkSize() (xhttpRange, error) {
	n := c.normalized()
	return n.uplinkChunkSize, n.uplinkChunkSizeErr
}

var xhttpPredefinedTable = map[string]string{
	"ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"BASE36":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Base62":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"HEX":      "0123456789ABCDEF",
	"alphabet": "abcdefghijklmnopqrstuvwxyz",
	"base36":   "0123456789abcdefghijklmnopqrstuvwxyz",
	"hex":      "0123456789abcdef",
	"number":   "0123456789",
}

func (c *xhttpConfig) GetGenerateSessionID() (func() string, error) {
	sessionTable := c.SessionTable
	switch sessionTable {
	case "":
		return func() string {
			var b [16]byte
			_, _ = crand.Read(b[:])
			return hex.EncodeToString(b[:])
		}, nil
	case "uuid":
		return func() string {
			var b [16]byte
			_, _ = crand.Read(b[:])
			b[6] = (b[6] & 0x0f) | 0x40
			b[8] = (b[8] & 0x3f) | 0x80
			return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
		}, nil
	default:
		if predefined, ok := xhttpPredefinedTable[sessionTable]; ok {
			sessionTable = predefined
		}
		sessionLength, err := xhttpParseRange(c.SessionLength, "16-32")
		if err != nil {
			return nil, fmt.Errorf("invalid session-length: %w", err)
		}
		room := xhttpRoomSize(len(sessionTable), sessionLength.Min, sessionLength.Max)
		if room.Cmp(big.NewInt(2<<30)) < 0 {
			return nil, errors.New("session-table or session-length is too small")
		}
		if sessionLength.Min <= 0 {
			return nil, errors.New("session-length must be greater than 0")
		}
		for i := 0; i < len(sessionTable); i++ {
			if sessionTable[i] >= 0x80 {
				return nil, errors.New("session-table must contain only ASCII characters")
			}
		}
		return func() string {
			length := sessionLength.Rand()
			id := make([]byte, length)
			for i := range id {
				id[i] = sessionTable[rand.IntN(len(sessionTable))]
			}
			return string(id)
		}, nil
	}
}

func xhttpRoomSize(tableSize int, min, max int) *big.Int {
	base := big.NewInt(int64(tableSize))
	sum := new(big.Int)
	term := new(big.Int)
	for k := min; k <= max; k++ {
		term.Exp(base, big.NewInt(int64(k)), nil)
		sum.Add(sum, term)
	}
	return sum
}

func xhttpAppendToPath(path, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}
