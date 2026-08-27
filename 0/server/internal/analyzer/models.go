package analyzer

import "time"

// EmailMetadata holds parsed RFC 5322 standard header fields
type EmailMetadata struct {
	Subject       string    `json:"subject"`
	From          string    `json:"from"`
	SenderAddress string    `json:"sender_address"`
	SenderName    string    `json:"sender_name"`
	To            []string  `json:"to"`
	Cc            []string  `json:"cc,omitempty"`
	ReplyTo       string    `json:"reply_to,omitempty"`
	ReturnPath    string    `json:"return_path,omitempty"`
	Date          time.Time `json:"date"`
	DateRaw       string    `json:"date_raw"`
	MessageID     string    `json:"message_id,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	ContentType   string    `json:"content_type"`
	BodyPreview   string    `json:"body_preview,omitempty"`
	RawBody       string    `json:"raw_body,omitempty"`
	BodyHTML      string    `json:"body_html,omitempty"`
	RawHeaders    string    `json:"raw_headers"`
}

// HopInfo represents one routing hop from a Received: header
type HopInfo struct {
	HopNumber          int     `json:"hop_number"`
	IP                 string  `json:"ip"`
	HostnameFrom       string  `json:"hostname_from,omitempty"`
	HostnameBy         string  `json:"hostname_by,omitempty"`
	Protocol           string  `json:"protocol,omitempty"`
	Timestamp          string  `json:"timestamp,omitempty"`
	Country            string  `json:"country"`
	CountryCode        string  `json:"country_code"`
	City               string  `json:"city"`
	Latitude           float64 `json:"latitude"`
	Longitude          float64 `json:"longitude"`
	Org                string  `json:"org"`
	ASN                string  `json:"asn,omitempty"`
	IsTor              bool    `json:"is_tor"`
	IsPrivate          bool    `json:"is_private"`
	IsSuspicious       bool    `json:"is_suspicious"`
	TransitTimeSeconds float64 `json:"transit_time_seconds"`
	Details            string  `json:"details,omitempty"`
}

// AuthCheckResult holds result for one auth protocol (SPF/DKIM/DMARC)
type AuthCheckResult struct {
	Result          string `json:"result"`
	Domain          string `json:"domain,omitempty"`
	Selector        string `json:"selector,omitempty"`
	SignaturesFound int    `json:"signatures_found,omitempty"`
	SenderIP        string `json:"sender_ip,omitempty"`
	Policy          string `json:"policy,omitempty"`
	Alignment       string `json:"alignment,omitempty"`
	Details         string `json:"details"`
}

// DomainAlignmentInfo reports cross-header domain consistency
type DomainAlignmentInfo struct {
	FromDomain        string `json:"from_domain"`
	ReturnPathDomain  string `json:"return_path_domain"`
	ReplyToDomain     string `json:"reply_to_domain"`
	DKIMDomain        string `json:"dkim_domain,omitempty"`
	IsAligned         bool   `json:"is_aligned"`
	LookalikeDetected bool   `json:"lookalike_detected"`
	TargetBrand       string `json:"target_brand,omitempty"`
	Details           string `json:"details"`
}

// SecurityChecks groups all email authentication results
type SecurityChecks struct {
	SPF             AuthCheckResult     `json:"spf"`
	DKIM            AuthCheckResult     `json:"dkim"`
	DMARC           AuthCheckResult     `json:"dmarc"`
	DomainAlignment DomainAlignmentInfo `json:"domain_alignment"`
}

// ThreatIndicator is a single discrete forensic detection flag
type ThreatIndicator struct {
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	MitreID     string `json:"mitre_id,omitempty"`
}

// ExtractedURL is a link found in the email body
type ExtractedURL struct {
	URL           string `json:"url"`
	DisplayText   string `json:"display_text"`
	IsDeceptive   bool   `json:"is_deceptive"`
	IsIPAddress   bool   `json:"is_ip_address"`
	SuspiciousTLD bool   `json:"suspicious_tld"`
	RiskLevel     string `json:"risk_level"` // MALICIOUS, SUSPICIOUS, CLEAN
	Reason        string `json:"reason,omitempty"`
}

// AttachmentInfo is metadata for an attached file
type AttachmentInfo struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
	MD5         string `json:"md5"`
	SHA256      string `json:"sha256"`
	IsDangerous bool   `json:"is_dangerous"`
	Reason      string `json:"reason,omitempty"`
}

// NLPAnalysis holds heuristic phishing content markers
type NLPAnalysis struct {
	UrgencyScore         int      `json:"urgency_score"`
	FinancialIntent      bool     `json:"financial_intent"`
	CredentialHarvesting bool     `json:"credential_harvesting"`
	CoercionMarkers      []string `json:"coercion_markers"`
	UrgencyKeywords      []string `json:"urgency_keywords"`
	Summary              string   `json:"summary"`
}

// AnalysisResult is the complete POST /api/v1/analyze JSON response
type AnalysisResult struct {
	Metadata         EmailMetadata     `json:"metadata"`
	SecurityChecks   SecurityChecks    `json:"security_checks"`
	RiskScore        int               `json:"risk_score"`
	RiskLevel        string            `json:"risk_level"` // CLEAN, LOW_RISK, SUSPICIOUS, MALICIOUS
	Verdict          string            `json:"verdict"`
	Hops             []HopInfo         `json:"hops"`
	ThreatIndicators []ThreatIndicator `json:"threat_indicators"`
	NLPAnalysis      NLPAnalysis       `json:"nlp_analysis"`
	ExtractedURLs    []ExtractedURL    `json:"extracted_urls"`
	Attachments      []AttachmentInfo  `json:"attachments"`
	AnalysisDuration string            `json:"analysis_duration"`
}

// SampleFixture is a pre-loaded attack scenario for demo
type SampleFixture struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Filename    string `json:"filename"`
	Expected    string `json:"expected_verdict"`
}

// HealthResponse is the GET /api/v1/health response
type HealthResponse struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	GeoIPStatus string `json:"geoip_status"`
	SamplesPath string `json:"samples_path"`
}

// AnalyzeRequest is the JSON body for sample analysis
type AnalyzeRequest struct {
	SampleID   string `json:"sample_id,omitempty"`
	RawContent string `json:"raw_content,omitempty"`
}
