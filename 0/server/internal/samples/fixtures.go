package samples

import (
	"embed"
	"fmt"

	"email-threat-forensics/internal/analyzer"
)

//go:embed *.eml
var emlFS embed.FS

// Fixtures is the registry of all pre-loaded sample email scenarios
var Fixtures = []analyzer.SampleFixture{
	{
		ID: "phishing_paypal", Name: "PayPal Account Suspended (Spoofed)",
		Category:    "Credential Phishing / Brand Impersonation",
		Description: "Classic credential phishing – spoofed PayPal domain with Tor origin, DMARC FAIL, deceptive links.",
		Filename:    "phishing_paypal.eml", Expected: "CRITICAL_BRAND_SPOOFING",
	},
	{
		ID: "bec_wire_transfer", Name: "CEO Wire Transfer Request (BEC)",
		Category:    "Business Email Compromise",
		Description: "CFO impersonation BEC attack requesting urgent $48,000 wire transfer via Reply-To hijack.",
		Filename:    "bec_wire_transfer.eml", Expected: "HIGH_CONFIDENCE_PHISHING",
	},
	{
		ID: "malware_invoice", Name: "Urgent Invoice with Malware ISO",
		Category:    "Malware Delivery",
		Description: "Fake invoice with a dangerous .iso disk image attachment used for malware container-bypass delivery.",
		Filename:    "malware_invoice.eml", Expected: "MALWARE_DELIVERY_CAMPAIGN",
	},
	{
		ID: "crypto_scam", Name: "Cryptocurrency Investment Scam",
		Category:    "Financial Fraud / Advance Fee",
		Description: "Advance-fee cryptocurrency scam with offshore relay routing and suspicious TLD phishing link.",
		Filename:    "crypto_scam.eml", Expected: "CONFIRMED_MALICIOUS",
	},
	{
		ID: "legitimate_google", Name: "Legitimate Google Workspace Alert",
		Category:    "Legitimate Email (Control)",
		Description: "Authentic Google Workspace security notification. All authentication passes. Clean routing.",
		Filename:    "legitimate_google.eml", Expected: "LIKELY_LEGITIMATE",
	},
}

// ReadSample returns raw EML bytes for a given sample ID
func ReadSample(id string) ([]byte, error) {
	for _, f := range Fixtures {
		if f.ID == id {
			return emlFS.ReadFile(f.Filename)
		}
	}
	return nil, fmt.Errorf("sample '%s' not found", id)
}

// List returns the fixture registry (without raw content)
func List() []analyzer.SampleFixture {
	return Fixtures
}
