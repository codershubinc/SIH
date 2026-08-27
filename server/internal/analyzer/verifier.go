package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	spfRe   = regexp.MustCompile(`(?i)\bspf=(pass|fail|softfail|neutral|none|permerror|temperror)\b(?:\s+\(([^)]+)\))?`)
	dkimRe  = regexp.MustCompile(`(?i)\bdkim=(pass|fail|none|neutral|permerror|temperror)\b(?:\s+header\.(?:i|d)=(\S+))?`)
	dmarcRe = regexp.MustCompile(`(?i)\bdmarc=(pass|fail|none|temperror|permerror)\b`)

	dkimDomainRe   = regexp.MustCompile(`(?i)\bd=([a-zA-Z0-9.\-]+)`)
	dkimSelectorRe = regexp.MustCompile(`(?i)\bs=([a-zA-Z0-9.\-]+)`)

	receivedSpfRe = regexp.MustCompile(`(?i)^(pass|fail|softfail|neutral|none|permerror)\b(?:\s+\(([^)]+)\))?`)

	brandLookalikes = map[string][]string{
		"PayPal":    {"paypa1", "paypal-security", "pay-pal", "paypai", "paypa1-"},
		"Microsoft": {"micros0ft", "microsoft-support", "o365-verify", "ms-login", "office365-"},
		"Google":    {"g00gle", "goog1e", "google-security", "gmail-support"},
		"Apple":     {"app1e", "apple-id", "icloud-verify", "appleid-"},
		"Amazon":    {"amaz0n", "amazon-security", "aws-billing"},
		"Netflix":   {"netf1ix", "netflix-billing", "netflix-update"},
		"DHL":       {"dhl-tracking", "dhl-parcel", "dhl-delivery-"},
		"FedEx":     {"fedx", "fedex-delivery", "fedex-notice"},
		"Chase":     {"chas3", "chase-alert", "chase-online-"},
		"Meta":      {"faceb00k", "meta-security", "instagram-badge"},
	}
)

// Verify runs all authentication checks and returns SecurityChecks
func Verify(hdrs map[string][]string, fromAddr, senderName, returnPath, replyTo, originIP string) SecurityChecks {
	fromDomain := extractDomain(fromAddr)
	rpDomain := extractDomain(returnPath)
	rtDomain := extractDomain(replyTo)

	authResults := strings.Join(hdrs["Authentication-Results"], " ")
	receivedSPF := strings.Join(hdrs["Received-Spf"], " ")
	dkimSigs := hdrs["Dkim-Signature"]

	spf := evalSPF(authResults, receivedSPF, originIP, fromDomain, rpDomain)
	dkim := evalDKIM(authResults, dkimSigs, fromDomain)
	align := evalAlignment(fromDomain, rpDomain, rtDomain, dkim.Domain, senderName)
	dmarc := evalDMARC(authResults, spf, dkim, align, fromDomain)

	return SecurityChecks{SPF: spf, DKIM: dkim, DMARC: dmarc, DomainAlignment: align}
}

func extractDomain(email string) string {
	email = strings.Trim(email, "<> ")
	if parts := strings.Split(email, "@"); len(parts) > 1 {
		return strings.ToLower(strings.TrimSpace(parts[1]))
	}
	return strings.ToLower(email)
}

func evalSPF(authResults, receivedSPF, ip, fromDomain, rpDomain string) AuthCheckResult {
	r := AuthCheckResult{Result: "NONE", SenderIP: ip, Domain: rpDomain}
	if r.Domain == "" {
		r.Domain = fromDomain
	}
	combined := authResults + " " + receivedSPF
	if m := spfRe.FindStringSubmatch(combined); len(m) > 1 {
		r.Result = strings.ToUpper(m[1])
		if len(m) > 2 {
			r.Details = m[2]
		}
	} else if receivedSPF != "" {
		if m := receivedSpfRe.FindStringSubmatch(strings.TrimSpace(receivedSPF)); len(m) > 1 {
			r.Result = strings.ToUpper(m[1])
			if len(m) > 2 {
				r.Details = m[2]
			}
		}
	}
	if r.Details == "" {
		switch r.Result {
		case "PASS":
			r.Details = fmt.Sprintf("Sender IP %s is authorized for domain %s", ip, r.Domain)
		case "FAIL":
			r.Details = fmt.Sprintf("Hard Fail: IP %s is NOT authorized to send for %s", ip, r.Domain)
		case "SOFTFAIL":
			r.Details = fmt.Sprintf("Soft Fail: IP %s is suspicious but not explicitly forbidden", ip)
		case "NEUTRAL":
			r.Details = "Domain makes no assertion about sender IP authorization"
		default:
			r.Details = fmt.Sprintf("No SPF record found or verified for %s", r.Domain)
		}
	}
	return r
}

func evalDKIM(authResults string, sigs []string, fromDomain string) AuthCheckResult {
	r := AuthCheckResult{Result: "NONE", SignaturesFound: len(sigs)}
	for _, sig := range sigs {
		if m := dkimDomainRe.FindStringSubmatch(sig); len(m) > 1 {
			r.Domain = strings.ToLower(m[1])
		}
		if m := dkimSelectorRe.FindStringSubmatch(sig); len(m) > 1 {
			r.Selector = m[1]
		}
	}
	if m := dkimRe.FindStringSubmatch(authResults); len(m) > 1 {
		r.Result = strings.ToUpper(m[1])
		if len(m) > 2 && m[2] != "" {
			r.Domain = strings.ToLower(strings.Trim(m[2], "@"))
		}
	} else if len(sigs) > 0 && r.Domain != "" {
		if r.Domain == fromDomain || strings.HasSuffix(fromDomain, "."+r.Domain) {
			r.Result = "PASS"
		} else {
			r.Result = "FAIL"
		}
	}
	if r.Details == "" {
		switch r.Result {
		case "PASS":
			r.Details = fmt.Sprintf("Valid cryptographic DKIM signature for domain %s (selector: %s)", r.Domain, r.Selector)
		case "FAIL":
			r.Details = fmt.Sprintf("DKIM signature failed verification for domain %s", r.Domain)
		default:
			r.Details = "No DKIM signature attached to this message"
		}
	}
	return r
}

func evalDMARC(authResults string, spf, dkim AuthCheckResult, align DomainAlignmentInfo, fromDomain string) AuthCheckResult {
	r := AuthCheckResult{Result: "NONE", Domain: fromDomain, Policy: "NONE", Alignment: "UNALIGNED"}
	if m := dmarcRe.FindStringSubmatch(authResults); len(m) > 1 {
		r.Result = strings.ToUpper(m[1])
	} else {
		spfOK := spf.Result == "PASS" && (spf.Domain == fromDomain || strings.HasSuffix(fromDomain, "."+spf.Domain))
		dkimOK := dkim.Result == "PASS" && (dkim.Domain == fromDomain || strings.HasSuffix(fromDomain, "."+dkim.Domain))
		if spfOK || dkimOK {
			r.Result = "PASS"
			r.Alignment = "ALIGNED"
			r.Policy = "REJECT"
		} else if spf.Result == "FAIL" || dkim.Result == "FAIL" {
			r.Result = "FAIL"
			r.Policy = "REJECT"
		}
	}
	if align.IsAligned {
		r.Alignment = "ALIGNED"
	}
	if r.Details == "" {
		switch r.Result {
		case "PASS":
			r.Details = fmt.Sprintf("DMARC PASSED for '%s' – identifier alignment satisfied", fromDomain)
		case "FAIL":
			r.Details = fmt.Sprintf("DMARC FAILED for '%s' – neither SPF nor DKIM aligned with header From", fromDomain)
		default:
			r.Details = fmt.Sprintf("No DMARC policy found for '%s'", fromDomain)
		}
	}
	return r
}

func evalAlignment(fromDomain, rpDomain, rtDomain, dkimDomain, senderName string) DomainAlignmentInfo {
	info := DomainAlignmentInfo{
		FromDomain: fromDomain, ReturnPathDomain: rpDomain,
		ReplyToDomain: rtDomain, DKIMDomain: dkimDomain, IsAligned: true,
	}
	if rpDomain != "" && rpDomain != fromDomain &&
		!strings.HasSuffix(fromDomain, "."+rpDomain) && !strings.HasSuffix(rpDomain, "."+fromDomain) {
		info.IsAligned = false
	}
	if rtDomain != "" && rtDomain != fromDomain && !strings.HasSuffix(fromDomain, "."+rtDomain) {
		info.IsAligned = false
	}
	// Brand lookalike check
	corpus := strings.ToLower(fromDomain + " " + senderName + " " + rpDomain)
	for brand, patterns := range brandLookalikes {
		for _, p := range patterns {
			if strings.Contains(corpus, p) {
				info.LookalikeDetected = true
				info.TargetBrand = brand
				info.Details = fmt.Sprintf("Lookalike pattern '%s' detected impersonating brand '%s'", p, brand)
				break
			}
		}
		if info.LookalikeDetected {
			break
		}
	}
	// Display name impersonation
	if !info.LookalikeDetected {
		nameLower := strings.ToLower(senderName)
		for brand := range brandLookalikes {
			bLower := strings.ToLower(brand)
			if strings.Contains(nameLower, bLower) {
				domainNoBrand := !strings.Contains(strings.ToLower(fromDomain), strings.ReplaceAll(bLower, " ", ""))
				if domainNoBrand {
					info.LookalikeDetected = true
					info.TargetBrand = brand
					info.Details = fmt.Sprintf("Display name '%s' impersonates '%s' while sending from '%s'", senderName, brand, fromDomain)
					break
				}
			}
		}
	}
	if info.Details == "" {
		if info.IsAligned {
			info.Details = "Full domain alignment: From, Return-Path, and Reply-To are consistent"
		} else {
			info.Details = fmt.Sprintf("Domain mismatch: From='%s', Return-Path='%s', Reply-To='%s'", fromDomain, rpDomain, rtDomain)
		}
	}
	return info
}
