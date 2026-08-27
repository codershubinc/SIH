package analyzer

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	ipv4Re    = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	bracketIP = regexp.MustCompile(`\[([0-9a-fA-F.:]+)\]`)
	fromRe    = regexp.MustCompile(`(?i)\bfrom\s+([^\s\(\)\[\];,]+)`)
	byRe      = regexp.MustCompile(`(?i)\bby\s+([^\s\(\)\[\];,]+)`)
	withRe    = regexp.MustCompile(`(?i)\bwith\s+([^\s;,]+)`)
	spaceRe   = regexp.MustCompile(`\s+`)

	timeLayouts = []string{
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 -0700 (MST)",
		"Mon, 02 Jan 2006 15:04:05 -0700",
		"Mon, 02 Jan 2006 15:04:05 -0700 (MST)",
		"2 Jan 2006 15:04:05 -0700",
		"02 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 MST",
		"2006-01-02T15:04:05Z07:00",
	}
)

// ParseHops takes raw Received headers (newest-first as in an EML file) and
// returns chronologically ordered hop list (origin = index 0).
func ParseHops(receivedHeaders []string) []HopInfo {
	if len(receivedHeaders) == 0 {
		return nil
	}

	// Reverse to get chronological order (oldest first)
	chrono := make([]string, len(receivedHeaders))
	for i, h := range receivedHeaders {
		chrono[len(receivedHeaders)-1-i] = h
	}

	var hops []HopInfo
	var prevTime time.Time

	for idx, raw := range chrono {
		clean := spaceRe.ReplaceAllString(
			strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", " "), "\n", " "),
			" ",
		)

		ip := extractIP(clean)
		hostnameFrom := regexFirst(fromRe, clean)
		hostnameBy := regexFirst(byRe, clean)
		protocol := regexFirst(withRe, clean)
		if protocol == "" {
			protocol = "SMTP"
		}

		tsStr, tsTime := parseHopTime(clean)

		var transit float64
		if !tsTime.IsZero() && !prevTime.IsZero() {
			d := tsTime.Sub(prevTime).Seconds()
			if d >= 0 && d < 86400 {
				transit = d
			}
			prevTime = tsTime
		} else if !tsTime.IsZero() {
			prevTime = tsTime
		}

		geo := Resolve(ip, hostnameFrom+" "+hostnameBy)

		hop := HopInfo{
			HopNumber:          idx + 1,
			IP:                 ip,
			HostnameFrom:       hostnameFrom,
			HostnameBy:         hostnameBy,
			Protocol:           protocol,
			Timestamp:          tsStr,
			Country:            geo.Country,
			CountryCode:        geo.CountryCode,
			City:               geo.City,
			Latitude:           geo.Latitude,
			Longitude:          geo.Longitude,
			Org:                geo.Org,
			ASN:                geo.ASN,
			IsTor:              geo.IsTor,
			IsPrivate:          geo.IsPrivate,
			IsSuspicious:       geo.IsSuspicious,
			TransitTimeSeconds: transit,
		}

		if hop.IP == "" {
			hop.IP = "Internal/Hidden"
			hop.Country = "Local Gateway"
			hop.City = "Internal Relay"
			hop.Org = hostnameBy
		}

		switch {
		case hop.IsTor:
			hop.Details = "Origin is a known anonymous Tor Exit Node relay"
		case hop.IsSuspicious:
			hop.Details = fmt.Sprintf("Routed via suspicious / offshore hosting: %s", hop.Org)
		case hop.IsPrivate:
			hop.Details = "RFC1918 private network – corporate internal relay"
		default:
			hop.Details = fmt.Sprintf("Legitimate MTA hop in %s via %s", hop.Country, hop.Org)
		}

		hops = append(hops, hop)
	}
	return hops
}

func extractIP(s string) string {
	// Prefer [IP] bracket notation
	for _, m := range bracketIP.FindAllStringSubmatch(s, -1) {
		if len(m) > 1 && net.ParseIP(m[1]) != nil {
			return m[1]
		}
	}
	// Fallback plain IPv4
	for _, candidate := range ipv4Re.FindAllString(s, -1) {
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	return ""
}

func regexFirst(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) > 1 {
		return strings.Trim(strings.TrimSpace(m[1]), "<>[];(),")
	}
	return ""
}

func parseHopTime(s string) (string, time.Time) {
	idx := strings.LastIndex(s, ";")
	if idx == -1 {
		return "", time.Time{}
	}
	raw := strings.TrimSpace(s[idx+1:])
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC().Format(time.RFC3339), t
		}
	}
	return raw, time.Time{}
}
