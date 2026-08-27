package analyzer

import (
	"fmt"
	"strings"
)

// urgency keywords that raise phishing heuristic score
var urgencyPhrases = []string{
	"your account has been suspended", "account suspended", "verify your account",
	"click here immediately", "immediate action required", "action required",
	"login attempt detected", "unauthorized access", "unusual activity",
	"confirm your identity", "verify within 24 hours", "limited time",
	"your password has been compromised", "account will be closed",
	"billing information required", "update your payment", "invoice attached",
	"final notice", "account on hold", "security alert", "important notice",
	"we detected suspicious", "you must verify", "click below to verify",
	"your account has been locked", "restore access", "reactivate your account",
}

var financialPhrases = []string{
	"wire transfer", "bank account", "routing number", "payment required",
	"outstanding invoice", "ach transfer", "paypal", "bitcoin", "crypto payment",
	"gift card", "itunes card", "google play card", "western union", "money order",
}

var credentialPhrases = []string{
	"enter your password", "confirm password", "username and password",
	"sign in to verify", "login to continue", "verify your email",
	"update your credentials", "account credentials", "reset your password",
}

var coercionPhrases = []string{
	"do not ignore", "failure to comply", "legal action will be taken",
	"this is your final warning", "act now", "respond immediately",
	"time-sensitive", "expires today", "last chance", "you have been selected",
}

// NLPAnalyse performs heuristic content scoring on email body
func NLPAnalyse(body string) NLPAnalysis {
	lower := strings.ToLower(body)
	result := NLPAnalysis{}

	var urgencyKWs []string
	var coercionMarkers []string
	urgencyScore := 0

	for _, phrase := range urgencyPhrases {
		if strings.Contains(lower, phrase) {
			urgencyKWs = append(urgencyKWs, phrase)
			urgencyScore += 10
		}
	}
	for _, phrase := range coercionPhrases {
		if strings.Contains(lower, phrase) {
			coercionMarkers = append(coercionMarkers, phrase)
			urgencyScore += 8
		}
	}
	for _, phrase := range financialPhrases {
		if strings.Contains(lower, phrase) {
			result.FinancialIntent = true
			urgencyScore += 7
			break
		}
	}
	for _, phrase := range credentialPhrases {
		if strings.Contains(lower, phrase) {
			result.CredentialHarvesting = true
			urgencyScore += 12
			break
		}
	}

	if urgencyScore > 100 {
		urgencyScore = 100
	}
	result.UrgencyScore = urgencyScore
	result.UrgencyKeywords = urgencyKWs
	result.CoercionMarkers = coercionMarkers

	switch {
	case urgencyScore >= 70:
		result.Summary = "Extremely high urgency language. Classic phishing emotional manipulation pattern detected."
	case urgencyScore >= 40:
		result.Summary = "Elevated urgency markers. Likely social engineering attempt."
	case urgencyScore >= 20:
		result.Summary = "Moderate urgency tone. Manual review recommended."
	default:
		result.Summary = "Low urgency content. No strong phishing language detected."
	}
	return result
}

// Analyse assembles all threat indicators and computes final risk score
func Analyse(
	security SecurityChecks,
	hops []HopInfo,
	urls []ExtractedURL,
	attachments []AttachmentInfo,
	nlp NLPAnalysis,
	metadata EmailMetadata,
) ([]ThreatIndicator, int, string, string) {

	var indicators []ThreatIndicator
	score := 0

	// ─── Authentication Failures ──────────────────────────────────────────
	if security.SPF.Result == "FAIL" {
		indicators = append(indicators, ThreatIndicator{
			Severity: "CRITICAL", Category: "Authentication",
			Title:       "SPF Hard Fail",
			Description: fmt.Sprintf("Sender IP is NOT authorised to send mail for domain '%s'. %s", security.SPF.Domain, security.SPF.Details),
			MitreID:     "T1566",
		})
		score += 20
	} else if security.SPF.Result == "SOFTFAIL" {
		indicators = append(indicators, ThreatIndicator{
			Severity: "HIGH", Category: "Authentication",
			Title:       "SPF Soft Fail",
			Description: security.SPF.Details,
			MitreID:     "T1566",
		})
		score += 10
	}

	if security.DKIM.Result == "FAIL" {
		indicators = append(indicators, ThreatIndicator{
			Severity: "CRITICAL", Category: "Authentication",
			Title:       "DKIM Signature Failure",
			Description: security.DKIM.Details,
			MitreID:     "T1566",
		})
		score += 20
	} else if security.DKIM.Result == "NONE" {
		indicators = append(indicators, ThreatIndicator{
			Severity: "MEDIUM", Category: "Authentication",
			Title:       "No DKIM Signature",
			Description: "Email has no DKIM cryptographic signature. Cannot verify message integrity.",
			MitreID:     "T1566",
		})
		score += 8
	}

	if security.DMARC.Result == "FAIL" {
		indicators = append(indicators, ThreatIndicator{
			Severity: "CRITICAL", Category: "Authentication",
			Title:       "DMARC Policy Failure",
			Description: security.DMARC.Details,
			MitreID:     "T1566.001",
		})
		score += 20
	}

	if !security.DomainAlignment.IsAligned {
		indicators = append(indicators, ThreatIndicator{
			Severity: "HIGH", Category: "Domain Spoofing",
			Title:       "Cross-Header Domain Mismatch",
			Description: security.DomainAlignment.Details,
			MitreID:     "T1566.001",
		})
		score += 15
	}

	if security.DomainAlignment.LookalikeDetected {
		indicators = append(indicators, ThreatIndicator{
			Severity: "CRITICAL", Category: "Brand Impersonation",
			Title:       fmt.Sprintf("%s Brand Impersonation", security.DomainAlignment.TargetBrand),
			Description: security.DomainAlignment.Details,
			MitreID:     "T1566.002",
		})
		score += 20
	}

	// ─── Routing / Hop Threats ────────────────────────────────────────────
	torCount := 0
	suspiciousCount := 0
	for _, hop := range hops {
		if hop.IsTor {
			torCount++
		}
		if hop.IsSuspicious && !hop.IsTor {
			suspiciousCount++
		}
	}
	if torCount > 0 {
		indicators = append(indicators, ThreatIndicator{
			Severity: "CRITICAL", Category: "Network Routing",
			Title:       fmt.Sprintf("Tor Exit Node Origin (%d hop(s))", torCount),
			Description: "Email originated from or transited through anonymous Tor Exit Node relays, indicating deliberate identity obfuscation.",
			MitreID:     "T1584.008",
		})
		score += 18
	}
	if suspiciousCount > 0 {
		indicators = append(indicators, ThreatIndicator{
			Severity: "HIGH", Category: "Network Routing",
			Title:       fmt.Sprintf("Suspicious Relay Infrastructure (%d hop(s))", suspiciousCount),
			Description: "Email was routed through known bulletproof hosting, offshore VPN, or suspicious relay infrastructure.",
			MitreID:     "T1583.006",
		})
		score += 10
	}

	// ─── Deceptive URLs ───────────────────────────────────────────────────
	maliciousURLCount := 0
	deceptiveCount := 0
	for _, u := range urls {
		if u.RiskLevel == "MALICIOUS" {
			maliciousURLCount++
		}
		if u.IsDeceptive {
			deceptiveCount++
		}
	}
	if deceptiveCount > 0 {
		indicators = append(indicators, ThreatIndicator{
			Severity: "CRITICAL", Category: "Deceptive Content",
			Title:       fmt.Sprintf("Deceptive Anchor Link Mismatch (%d link(s))", deceptiveCount),
			Description: "Email contains links whose visible text shows a trusted domain but the actual href navigates to a different (malicious) destination.",
			MitreID:     "T1204.001",
		})
		score += 15
	}
	if maliciousURLCount > 0 && deceptiveCount == 0 {
		indicators = append(indicators, ThreatIndicator{
			Severity: "HIGH", Category: "Deceptive Content",
			Title:       fmt.Sprintf("Malicious / Suspicious URLs (%d)", maliciousURLCount),
			Description: "Direct IP address links or high-risk phishing TLD domains detected in email body.",
			MitreID:     "T1204.001",
		})
		score += 10
	}

	// ─── Dangerous Attachments ────────────────────────────────────────────
	for _, att := range attachments {
		if att.IsDangerous {
			indicators = append(indicators, ThreatIndicator{
				Severity: "CRITICAL", Category: "Malware Delivery",
				Title:       fmt.Sprintf("Dangerous Attachment: %s", att.Filename),
				Description: fmt.Sprintf("Attachment '%s' is a %s – commonly used to deliver malware or bypass security controls.", att.Filename, att.Reason),
				MitreID:     "T1566.001",
			})
			score += 20
		}
	}

	// ─── NLP Phishing Markers ─────────────────────────────────────────────
	if nlp.UrgencyScore >= 60 {
		indicators = append(indicators, ThreatIndicator{
			Severity: "HIGH", Category: "Social Engineering",
			Title:       "High-Urgency Phishing Language",
			Description: fmt.Sprintf("Body contains %d urgency/coercion phrases. %s", len(nlp.UrgencyKeywords)+len(nlp.CoercionMarkers), nlp.Summary),
			MitreID:     "T1566.002",
		})
		score += 10
	} else if nlp.UrgencyScore >= 30 {
		indicators = append(indicators, ThreatIndicator{
			Severity: "MEDIUM", Category: "Social Engineering",
			Title:       "Elevated Urgency Language",
			Description: nlp.Summary,
			MitreID:     "T1566.002",
		})
		score += 5
	}

	if nlp.CredentialHarvesting {
		indicators = append(indicators, ThreatIndicator{
			Severity: "HIGH", Category: "Credential Phishing",
			Title:       "Credential Harvesting Attempt",
			Description: "Email body requests login credentials, password, or authentication information.",
			MitreID:     "T1056",
		})
		score += 10
	}

	if nlp.FinancialIntent {
		indicators = append(indicators, ThreatIndicator{
			Severity: "MEDIUM", Category: "Financial Fraud",
			Title:       "Financial Transaction Manipulation",
			Description: "Email contains language related to wire transfers, payment methods, or financial coercion.",
			MitreID:     "T1657",
		})
		score += 8
	}

	// ─── Mailer Fingerprint ───────────────────────────────────────────────
	ua := strings.ToLower(metadata.UserAgent)
	if strings.Contains(ua, "phpmailer") || strings.Contains(ua, "sendgrid-phishing") || strings.Contains(ua, "bulk-mailer") {
		indicators = append(indicators, ThreatIndicator{
			Severity: "MEDIUM", Category: "Infrastructure",
			Title:       "Suspicious Mailer Fingerprint",
			Description: fmt.Sprintf("X-Mailer/User-Agent '%s' is commonly associated with bulk phishing campaigns.", metadata.UserAgent),
			MitreID:     "T1583",
		})
		score += 5
	}

	if score > 100 {
		score = 100
	}

	// Determine risk level and verdict
	riskLevel, verdict := classifyRisk(score, indicators)
	return indicators, score, riskLevel, verdict
}

func classifyRisk(score int, indicators []ThreatIndicator) (string, string) {
	criticalCount := 0
	for _, i := range indicators {
		if i.Severity == "CRITICAL" {
			criticalCount++
		}
	}

	switch {
	case score >= 80 || criticalCount >= 3:
		verdict := "CONFIRMED_MALICIOUS"
		if hasCategory(indicators, "Brand Impersonation") {
			verdict = "CRITICAL_BRAND_SPOOFING"
		} else if hasCategory(indicators, "Malware Delivery") {
			verdict = "MALWARE_DELIVERY_CAMPAIGN"
		} else if hasCategory(indicators, "Credential Phishing") {
			verdict = "CREDENTIAL_PHISHING_ATTACK"
		}
		return "MALICIOUS", verdict

	case score >= 55 || criticalCount >= 2:
		return "MALICIOUS", "HIGH_CONFIDENCE_PHISHING"

	case score >= 35:
		return "SUSPICIOUS", "SUSPICIOUS_POTENTIAL_PHISHING"

	case score >= 15:
		return "LOW_RISK", "LOW_RISK_REVIEW_RECOMMENDED"

	default:
		return "CLEAN", "LIKELY_LEGITIMATE"
	}
}

func hasCategory(indicators []ThreatIndicator, cat string) bool {
	for _, i := range indicators {
		if i.Category == cat {
			return true
		}
	}
	return false
}
