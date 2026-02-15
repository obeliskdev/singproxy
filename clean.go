package singproxy

import (
	"fmt"
	"net/url"
	"strings"
)

func cleanBruteForce(cleanedURL string) string {
	schemeEnd := strings.Index(cleanedURL, "://")
	if schemeEnd != -1 {
		scheme := cleanedURL[:schemeEnd]
		rest := cleanedURL[schemeEnd+3:]

		switch scheme {
		case "ss":
			// Handles ss://user@host:port@comment format
			parts := strings.Split(cleanedURL, "@")
			if len(parts) > 2 {
				realHostAndPort := parts[len(parts)-2]
				userInfoPart := strings.Join(parts[:len(parts)-2], "@")
				cleanedURL = fmt.Sprintf("%s@%s", userInfoPart, realHostAndPort)
			}
		case "trojan", "hysteria2":
			if atIndex := strings.LastIndex(rest, "@"); atIndex > 0 {
				userInfo := rest[:atIndex]
				hostInfo := rest[atIndex+1:]
				safeUserInfo := strings.ReplaceAll(userInfo, "-->", "--")
				safeUserInfo = strings.ReplaceAll(safeUserInfo, " ", "%20")
				cleanedURL = fmt.Sprintf("%s://%s@%s", scheme, safeUserInfo, hostInfo)
			}
		case "vless":
			if atIndex := strings.LastIndex(rest, "@"); atIndex != -1 {
				hostPartStart := atIndex + 1
				hostAndQuery := rest[hostPartStart:]
				queryIndex := strings.Index(hostAndQuery, "?")
				hostPart := hostAndQuery
				if queryIndex != -1 {
					hostPart = hostAndQuery[:queryIndex]
				}
				if strings.Contains(hostPart, "---") {
					cleanHost := strings.Split(hostPart, "---")[0]
					cleanedURL = cleanedURL[:schemeEnd+3+atIndex+1] + cleanHost + cleanedURL[schemeEnd+3+atIndex+1+len(hostPart):]
				}
			}
		case "vmess":
			payload := cleanedURL[schemeEnd+3:]
			cleanedPayload := nonBase64Chars.ReplaceAllString(payload, "")
			cleanedURL = "vmess://" + cleanedPayload
		}
	}

	return cleanedURL
}

func cleanProxyURL(raw string) string {
	raw = strings.ReplaceAll(raw, "\u0026amp;", "&")
	raw = strings.ReplaceAll(raw, "\u0026", "&")
	raw = strings.ReplaceAll(raw, "&amp;", "&")
	raw = strings.ReplaceAll(raw, "&#38;", "&")

	noFragment := raw
	if i := strings.Index(raw, "#"); i != -1 {
		noFragment = raw[:i]
	}

	base, rawQuery := noFragment, ""
	if i := strings.Index(noFragment, "?"); i != -1 {
		base = noFragment[:i]
		rawQuery = noFragment[i+1:]
	}

	queryVals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return raw
	}

	queryVals.Del("ps")
	queryVals.Del("tag")
	queryVals.Del("label")
	queryVals.Del("remarks")

	queryStr := queryVals.Encode()
	if queryStr != "" {
		return base + "?" + queryStr
	}

	return cleanBruteForce(base)
}
