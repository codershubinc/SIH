package analyzer

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	urlRe        = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"'{}|\\^` + "`" + `\[\]]+`)
	anchorRe     = regexp.MustCompile(`(?i)<a\s[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)</a>`)
	htmlStripRe  = regexp.MustCompile(`<[^>]+>`)
	multiSpaceRe = regexp.MustCompile(`\s+`)

	suspiciousTLDs = map[string]bool{
		".xyz": true, ".top": true, ".tk": true, ".ml": true, ".ga": true,
		".cf": true, ".gq": true, ".cc": true, ".work": true, ".click": true,
		".live": true, ".loan": true, ".buzz": true, ".fit": true, ".surf": true,
		".cam": true, ".quest": true, ".monster": true, ".ru": true,
	}

	dangerousExts = map[string]string{
		".exe":  "Windows executable binary",
		".scr":  "Windows screensaver executable",
		".iso":  "Disk image – container-bypass malware delivery",
		".img":  "Disk image container",
		".vbs":  "VBScript executable",
		".js":   "JavaScript script",
		".jse":  "Encrypted JScript executable",
		".wsf":  "Windows Script File",
		".bat":  "Windows batch script",
		".cmd":  "Windows command script",
		".ps1":  "PowerShell script",
		".hta":  "HTML Application executable",
		".jar":  "Java executable archive",
		".docm": "Macro-enabled Word document",
		".xlsm": "Macro-enabled Excel spreadsheet",
		".lnk":  "Windows shortcut payload",
	}
)

// ParsedEML is the structured output of parsing a raw .eml file
type ParsedEML struct {
	Metadata      EmailMetadata
	Headers       map[string][]string
	ExtractedURLs []ExtractedURL
	Attachments   []AttachmentInfo
	ReceivedHdrs  []string // raw Received: values, newest-first
	RawBody       string
}

// ParseEML parses raw RFC 5322 bytes into a ParsedEML
func ParseEML(data []byte) (*ParsedEML, error) {
	data = stripMBoxEnvelope(data)
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("eml parse failed: %w", err)
	}

	// Build header map (canonical key -> values)
	hdrs := make(map[string][]string)
	var rawHdrBuf strings.Builder
	for k, vv := range msg.Header {
		key := canonicalKey(k)
		hdrs[key] = append(hdrs[key], vv...)
		for _, v := range vv {
			fmt.Fprintf(&rawHdrBuf, "%s: %s\n", k, v)
		}
	}

	// Core metadata
	subject := decodeMIMEHeader(msg.Header.Get("Subject"))
	fromRaw := msg.Header.Get("From")
	senderName, senderAddr := parseAddr(fromRaw)
	toList := parseAddrList(msg.Header.Get("To"))
	ccList := parseAddrList(msg.Header.Get("Cc"))
	_, replyToAddr := parseAddr(msg.Header.Get("Reply-To"))
	_, returnPath := parseAddr(msg.Header.Get("Return-Path"))
	dateRaw := msg.Header.Get("Date")
	parsedDate, _ := mail.ParseDate(dateRaw)
	msgID := msg.Header.Get("Message-Id")
	ua := msg.Header.Get("User-Agent")
	if ua == "" {
		ua = msg.Header.Get("X-Mailer")
	}
	ct := msg.Header.Get("Content-Type")
	if ct == "" {
		ct = "text/plain; charset=utf-8"
	}

	// Parse body parts
	textBody, htmlBody, attachments, _ := parseBody(msg.Body, ct)
	preview := buildPreview(textBody)
	if preview == "" {
		preview = buildPreview(stripHTML(htmlBody))
	}

	urls := extractURLs(textBody, htmlBody)

	return &ParsedEML{
		Metadata: EmailMetadata{
			Subject:       subject,
			From:          fromRaw,
			SenderAddress: senderAddr,
			SenderName:    senderName,
			To:            toList,
			Cc:            ccList,
			ReplyTo:       replyToAddr,
			ReturnPath:    returnPath,
			Date:          parsedDate,
			DateRaw:       dateRaw,
			MessageID:     msgID,
			UserAgent:     ua,
			ContentType:   ct,
			BodyPreview:   preview,
			RawBody:       textBody,
			BodyHTML:      htmlBody,
			RawHeaders:    rawHdrBuf.String(),
		},
		Headers:       hdrs,
		ExtractedURLs: urls,
		Attachments:   attachments,
		ReceivedHdrs:  hdrs["Received"],
		RawBody:       textBody + "\n" + htmlBody,
	}, nil
}

// stripMBoxEnvelope removes mbox "From " envelope line if present
func stripMBoxEnvelope(data []byte) []byte {
	if bytes.HasPrefix(data, []byte("From ")) {
		if idx := bytes.IndexByte(data, '\n'); idx != -1 {
			return data[idx+1:]
		}
	}
	return data
}

func decodeMIMEHeader(v string) string {
	dec := new(mime.WordDecoder)
	if out, err := dec.DecodeHeader(v); err == nil {
		return out
	}
	return v
}

func parseAddr(raw string) (string, string) {
	if raw == "" {
		return "", ""
	}
	if a, err := mail.ParseAddress(raw); err == nil {
		return decodeMIMEHeader(a.Name), a.Address
	}
	re := regexp.MustCompile(`<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?`)
	if m := re.FindStringSubmatch(raw); len(m) > 1 {
		return "", m[1]
	}
	return "", strings.Trim(raw, "<> ")
}

func parseAddrList(raw string) []string {
	if raw == "" {
		return nil
	}
	list, err := mail.ParseAddressList(raw)
	if err != nil {
		return []string{raw}
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Address)
	}
	return out
}

func canonicalKey(s string) string {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
		}
	}
	return strings.Join(parts, "-")
}

func parseBody(body io.Reader, ctHeader string) (string, string, []AttachmentInfo, error) {
	mediaType, params, err := mime.ParseMediaType(ctHeader)
	if err != nil {
		mediaType = "text/plain"
	}
	var textBuf, htmlBuf strings.Builder
	var attachments []AttachmentInfo

	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			partCT, partParams, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
			disp, dispParams, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
			fname := coalesce(part.FileName(), dispParams["filename"], partParams["name"])
			data, _ := io.ReadAll(part)

			if disp == "attachment" || fname != "" {
				attachments = append(attachments, buildAttachment(fname, partCT, data))
			} else if strings.HasPrefix(partCT, "multipart/") {
				t, h, atts, _ := parseBody(bytes.NewReader(data), part.Header.Get("Content-Type"))
				textBuf.WriteString(t)
				htmlBuf.WriteString(h)
				attachments = append(attachments, atts...)
			} else if partCT == "text/html" {
				htmlBuf.Write(data)
			} else {
				textBuf.Write(data)
			}
		}
	} else if mediaType == "text/html" {
		data, _ := io.ReadAll(body)
		htmlBuf.Write(data)
	} else {
		data, _ := io.ReadAll(body)
		textBuf.Write(data)
	}
	return textBuf.String(), htmlBuf.String(), attachments, nil
}

func buildAttachment(filename, ct string, data []byte) AttachmentInfo {
	if filename == "" {
		filename = "unnamed.bin"
	}
	filename = decodeMIMEHeader(filename)
	ext := strings.ToLower(filepath.Ext(filename))
	md5sum := md5.Sum(data)
	sha256sum := sha256.Sum256(data)
	reason := dangerousExts[ext]
	return AttachmentInfo{
		Filename:    filename,
		ContentType: ct,
		SizeBytes:   int64(len(data)),
		MD5:         hex.EncodeToString(md5sum[:]),
		SHA256:      hex.EncodeToString(sha256sum[:]),
		IsDangerous: reason != "",
		Reason:      reason,
	}
}

func extractURLs(text, html string) []ExtractedURL {
	urlMap := make(map[string]ExtractedURL)

	if html != "" {
		for _, m := range anchorRe.FindAllStringSubmatch(html, -1) {
			if len(m) > 2 {
				target := strings.TrimSpace(m[1])
				display := strings.TrimSpace(stripHTML(m[2]))
				if isHTTP(target) {
					urlMap[target] = evalURL(target, display)
				}
			}
		}
	}

	combined := text + " " + stripHTML(html)
	for _, u := range urlRe.FindAllString(combined, -1) {
		u = strings.Trim(u, ".,;:)\"'>")
		if isHTTP(u) {
			if _, exists := urlMap[u]; !exists {
				urlMap[u] = evalURL(u, u)
			}
		}
	}

	out := make([]ExtractedURL, 0, len(urlMap))
	for _, v := range urlMap {
		out = append(out, v)
	}
	return out
}

func evalURL(target, display string) ExtractedURL {
	eu := ExtractedURL{URL: target, DisplayText: display, RiskLevel: "CLEAN"}
	parsed, err := url.Parse(target)
	if err != nil {
		eu.RiskLevel = "SUSPICIOUS"
		eu.Reason = "Malformed URL"
		return eu
	}
	host := strings.ToLower(parsed.Hostname())

	if net.ParseIP(host) != nil {
		eu.IsIPAddress = true
		eu.RiskLevel = "MALICIOUS"
		eu.Reason = "Direct IP address in URL (no domain)"
	}
	for tld := range suspiciousTLDs {
		if strings.HasSuffix(host, tld) {
			eu.SuspiciousTLD = true
			if eu.RiskLevel != "MALICIOUS" {
				eu.RiskLevel = "SUSPICIOUS"
			}
			eu.Reason = fmt.Sprintf("Phishing-prone TLD %s", tld)
			break
		}
	}

	dispL := strings.ToLower(display)
	for _, trusted := range []string{"paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com", "bankofamerica.com"} {
		if strings.Contains(dispL, trusted) && !strings.Contains(host, trusted) {
			eu.IsDeceptive = true
			eu.RiskLevel = "MALICIOUS"
			eu.Reason = fmt.Sprintf("Anchor text shows trusted domain but href points to '%s'", host)
			break
		}
	}
	return eu
}

func isHTTP(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
func stripHTML(s string) string { return htmlStripRe.ReplaceAllString(s, " ") }
func buildPreview(s string) string {
	clean := strings.TrimSpace(multiSpaceRe.ReplaceAllString(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", " "), "\n", " "), " "))
	if len(clean) > 300 {
		return clean[:300] + "..."
	}
	return clean
}
func coalesce(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
