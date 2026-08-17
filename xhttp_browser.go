package singproxy

import (
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func xhttpChromeVersion() int {
	var startVersion = 144
	var timeStart = time.Date(2026, 1, 13, 0, 0, 0, 0, time.UTC).Unix() / 86400
	var timeCurrent = time.Now().Unix() / 86400
	var timeDiff = int(timeCurrent-timeStart-35) - int(math.Floor(math.Pow(rand.Float64(), 2)*105))
	return startVersion + (timeDiff / 35)
}

var xhttpSafariMinorMap = [25]int{0, 0, 0, 1, 1,
	1, 2, 2, 2, 2, 3, 3, 3, 4, 4,
	4, 5, 5, 5, 5, 5, 6, 6, 6, 6}

func xhttpCurlVersion() string {
	var timeCurrent = time.Now().Unix() / 86400
	var timeStart = time.Date(2023, 3, 20, 0, 0, 0, 0, time.UTC).Unix() / 86400
	var timeDiff = int(timeCurrent-timeStart-60) - int(math.Floor(math.Pow(rand.Float64(), 2)*165))
	var minorValue = timeDiff / 57
	return "8." + strconv.Itoa(minorValue) + ".0"
}

func xhttpFirefoxVersion() int {
	var timeCurrent = time.Now().Unix() / 86400
	var timeStart = time.Date(2024, 7, 29, 0, 0, 0, 0, time.UTC).Unix() / 86400
	var timeDiff = timeCurrent - timeStart - 25 - int64(math.Floor(math.Pow(rand.Float64(), 2)*50))
	return int(timeDiff/30) + 128
}

func xhttpSafariVersion() string {
	var anchoredTime = time.Now()
	var releaseYear = anchoredTime.Year()
	var splitPoint = time.Date(releaseYear, 9, 23, 0, 0, 0, 0, time.UTC)
	var delayedDays = int(math.Floor(math.Pow(rand.Float64(), 3) * 75))
	splitPoint = splitPoint.AddDate(0, 0, delayedDays)
	if anchoredTime.Compare(splitPoint) < 0 {
		releaseYear--
		splitPoint = time.Date(releaseYear, 9, 23, 0, 0, 0, 0, time.UTC)
		splitPoint = splitPoint.AddDate(0, 0, delayedDays)
	}
	var minorVersion = xhttpSafariMinorMap[(anchoredTime.Unix()-splitPoint.Unix())/1296000]
	return strconv.Itoa(releaseYear-1999) + "." + strconv.Itoa(minorVersion)
}

var xhttpClientHintGreaseNA = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
var xhttpClientHintVersionNA = []string{"8", "99", "24"}
var xhttpClientHintShuffle3 = [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
var xhttpClientHintShuffle4 = [][4]int{
	{0, 1, 2, 3}, {0, 1, 3, 2}, {0, 2, 1, 3}, {0, 2, 3, 1}, {0, 3, 1, 2}, {0, 3, 2, 1},
	{1, 0, 2, 3}, {1, 0, 3, 2}, {1, 2, 0, 3}, {1, 2, 3, 0}, {1, 3, 0, 2}, {1, 3, 2, 0},
	{2, 0, 1, 3}, {2, 0, 3, 1}, {2, 1, 0, 3}, {2, 1, 3, 0}, {2, 3, 0, 1}, {2, 3, 1, 0},
	{3, 0, 1, 2}, {3, 0, 2, 1}, {3, 1, 0, 2}, {3, 1, 2, 0}, {3, 2, 0, 1}, {3, 2, 1, 0}}

func xhttpGetGreasedChInvalidBrand(seed int) string {
	return "\"Not" + xhttpClientHintGreaseNA[seed%len(xhttpClientHintGreaseNA)] + "A" + xhttpClientHintGreaseNA[(seed+1)%len(xhttpClientHintGreaseNA)] + "Brand\";v=\"" + xhttpClientHintVersionNA[seed%len(xhttpClientHintVersionNA)] + "\""
}

func xhttpGetGreasedChOrder(brandLength int, seed int) []int {
	switch brandLength {
	case 1:
		return []int{0}
	case 2:
		return []int{seed % brandLength, (seed + 1) % brandLength}
	case 3:
		return xhttpClientHintShuffle3[seed%len(xhttpClientHintShuffle3)][:]
	default:
		return xhttpClientHintShuffle4[seed%len(xhttpClientHintShuffle4)][:]
	}
}

func xhttpGetUngreasedChUa(majorVersion int, forkName string) []string {
	baseChUa := make([]string, 0, 4)
	baseChUa = append(baseChUa, xhttpGetGreasedChInvalidBrand(majorVersion),
		"\"Chromium\";v=\""+strconv.Itoa(majorVersion)+"\"")
	switch forkName {
	case "chrome":
		baseChUa = append(baseChUa, "\"Google Chrome\";v=\""+strconv.Itoa(majorVersion)+"\"")
	case "edge":
		baseChUa = append(baseChUa, "\"Microsoft Edge\";v=\""+strconv.Itoa(majorVersion)+"\"")
	}
	return baseChUa
}

func xhttpGetGreasedChUa(majorVersion int, forkName string) string {
	ungreasedCh := xhttpGetUngreasedChUa(majorVersion, forkName)
	shuffleMap := xhttpGetGreasedChOrder(len(ungreasedCh), majorVersion)
	shuffledCh := make([]string, len(ungreasedCh))
	for i, e := range shuffleMap {
		shuffledCh[e] = ungreasedCh[i]
	}
	return strings.Join(shuffledCh, ", ")
}

type xhttpMasqueradeCache struct {
	day           int64
	chromeUA      string
	chromeSecCHUA string
	edgeUA        string
	edgeSecCHUA   string
	firefoxUA     string
	safariUA      string
	curlUA        string
}

func buildMasqueradeCache(day int64) xhttpMasqueradeCache {
	chromeVersion := xhttpChromeVersion()
	firefoxVersion := xhttpFirefoxVersion()
	cache := xhttpMasqueradeCache{day: day}
	cache.chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(chromeVersion) + ".0.0.0 Safari/537.36"
	cache.chromeSecCHUA = xhttpGetGreasedChUa(chromeVersion, "chrome")
	cache.edgeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(chromeVersion) + ".0.0.0 Safari/537.36 Edg/" + strconv.Itoa(chromeVersion) + ".0.0.0"
	cache.edgeSecCHUA = xhttpGetGreasedChUa(chromeVersion, "edge")
	cache.firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + strconv.Itoa(firefoxVersion) + ".0) Gecko/20100101 Firefox/" + strconv.Itoa(firefoxVersion) + ".0"
	cache.safariUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + xhttpSafariVersion() + " Safari/605.1.15"
	cache.curlUA = "curl/" + xhttpCurlVersion()
	return cache
}

func (c *xhttpConfig) masquerade() *xhttpMasqueradeCache {
	day := time.Now().Unix() / 86400
	c.masqMu.Lock()
	defer c.masqMu.Unlock()
	if c.masq.day != day {
		c.masq = buildMasqueradeCache(day)
	}
	return &c.masq
}

func (c *xhttpConfig) applyMasqueradedHeaders(header http.Header, variant string) {
	browser := "chrome"
	if ua := header.Get("User-Agent"); ua != "" {
		switch ua {
		case "chrome", "firefox", "safari", "edge", "curl", "golang":
			browser = ua
		}
	}
	cache := c.masquerade()
	switch browser {
	case "chrome":
		header["Sec-CH-UA"] = []string{cache.chromeSecCHUA}
		header["Sec-CH-UA-Mobile"] = []string{"?0"}
		header["Sec-CH-UA-Platform"] = []string{"\"Windows\""}
		header["DNT"] = []string{"1"}
		header.Set("User-Agent", cache.chromeUA)
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "edge":
		header["Sec-CH-UA"] = []string{cache.edgeSecCHUA}
		header["Sec-CH-UA-Mobile"] = []string{"?0"}
		header["Sec-CH-UA-Platform"] = []string{"\"Windows\""}
		header["DNT"] = []string{"1"}
		header.Set("User-Agent", cache.edgeUA)
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "firefox":
		header.Set("User-Agent", cache.firefoxUA)
		header["DNT"] = []string{"1"}
		header.Set("Accept-Language", "en-US,en;q=0.5")
	case "safari":
		header.Set("User-Agent", cache.safariUA)
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "golang":
		delete(header, "User-Agent")
		return
	case "curl":
		header.Set("User-Agent", cache.curlUA)
		return
	}
	switch variant {
	case "nav":
		if header.Get("Cache-Control") == "" {
			switch browser {
			case "chrome", "edge":
				header.Set("Cache-Control", "max-age=0")
			}
		}
		header.Set("Upgrade-Insecure-Requests", "1")
		if header.Get("Accept") == "" {
			switch browser {
			case "chrome", "edge":
				header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			case "firefox", "safari":
				header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			}
		}
		header.Set("Sec-Fetch-Site", "none")
		header.Set("Sec-Fetch-Mode", "navigate")
		switch browser {
		case "safari":
		default:
			header.Set("Sec-Fetch-User", "?1")
		}
		header.Set("Sec-Fetch-Dest", "document")
		header.Set("Priority", "u=0, i")
	case "ws":
		header.Set("Sec-Fetch-Mode", "websocket")
		switch browser {
		case "safari":
			header.Set("Sec-Fetch-Dest", "websocket")
		default:
			header.Set("Sec-Fetch-Dest", "empty")
		}
		header.Set("Sec-Fetch-Site", "same-origin")
		if header.Get("Cache-Control") == "" {
			header.Set("Cache-Control", "no-cache")
		}
		if header.Get("Pragma") == "" {
			header.Set("Pragma", "no-cache")
		}
		if header.Get("Accept") == "" {
			header.Set("Accept", "*/*")
		}
	case "fetch":
		header.Set("Sec-Fetch-Mode", "cors")
		header.Set("Sec-Fetch-Dest", "empty")
		header.Set("Sec-Fetch-Site", "same-origin")
		if header.Get("Priority") == "" {
			switch browser {
			case "chrome", "edge":
				header.Set("Priority", "u=1, i")
			case "firefox":
				header.Set("Priority", "u=4")
			case "safari":
				header.Set("Priority", "u=3, i")
			}
		}
		if header.Get("Cache-Control") == "" {
			header.Set("Cache-Control", "no-cache")
		}
		if header.Get("Pragma") == "" {
			header.Set("Pragma", "no-cache")
		}
		if header.Get("Accept") == "" {
			header.Set("Accept", "*/*")
		}
	}
}
