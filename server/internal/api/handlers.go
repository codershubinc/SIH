package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"email-threat-forensics/internal/analyzer"
	"email-threat-forensics/internal/samples"
)

const maxUploadSize = 10 << 20 // 10 MB

// HealthHandler handles GET /api/v1/health
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	JSON(w, http.StatusOK, analyzer.HealthResponse{
		Status:      "ok",
		Version:     "1.0.0",
		GeoIPStatus: "offline-db + online-fallback",
		SamplesPath: "embedded fs",
	})
}

// SamplesHandler handles GET /api/v1/samples
func SamplesHandler(w http.ResponseWriter, r *http.Request) {
	JSON(w, http.StatusOK, map[string]any{"samples": samples.List()})
}

// AnalyzeHandler handles POST /api/v1/analyze
func AnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	start := time.Now()

	ct := r.Header.Get("Content-Type")
	var rawEML []byte
	var err error

	// Branch: multipart file upload vs JSON (sample_id / raw_content)
	if len(ct) >= 19 && ct[:19] == "multipart/form-data" {
		rawEML, err = readMultipart(r)
	} else {
		rawEML, err = readJSON(r)
	}

	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(rawEML) == 0 {
		Error(w, http.StatusBadRequest, "empty email content")
		return
	}

	result, err := runAnalysis(rawEML)
	if err != nil {
		Error(w, http.StatusUnprocessableEntity, fmt.Sprintf("analysis failed: %v", err))
		return
	}

	result.AnalysisDuration = fmt.Sprintf("%.2fms", float64(time.Since(start).Microseconds())/1000)
	JSON(w, http.StatusOK, result)
}

func readMultipart(r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		return nil, fmt.Errorf("multipart parse error: %w", err)
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		return nil, fmt.Errorf("missing 'file' field in multipart form")
	}
	defer file.Close()
	return io.ReadAll(file)
}

func readJSON(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxUploadSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read request body")
	}

	var req analyzer.AnalyzeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		// Treat raw body as direct EML text
		return body, nil
	}

	if req.SampleID != "" {
		data, err := samples.ReadSample(req.SampleID)
		if err != nil {
			return nil, fmt.Errorf("sample not found: %s", req.SampleID)
		}
		return data, nil
	}
	if req.RawContent != "" {
		return []byte(req.RawContent), nil
	}

	// Fallback: treat body as raw EML
	return body, nil
}

func runAnalysis(rawEML []byte) (*analyzer.AnalysisResult, error) {
	// 1. Parse EML
	parsed, err := analyzer.ParseEML(rawEML)
	if err != nil {
		return nil, err
	}

	// 2. Parse routing hops
	hops := analyzer.ParseHops(parsed.ReceivedHdrs)

	// Derive origin IP from first (oldest) hop
	originIP := ""
	if len(hops) > 0 {
		originIP = hops[0].IP
	}

	// 3. Auth verification
	security := analyzer.Verify(
		parsed.Headers,
		parsed.Metadata.SenderAddress,
		parsed.Metadata.SenderName,
		parsed.Metadata.ReturnPath,
		parsed.Metadata.ReplyTo,
		originIP,
	)

	// 4. NLP analysis
	nlp := analyzer.NLPAnalyse(parsed.RawBody)

	// 5. Threat scoring
	indicators, score, riskLevel, verdict := analyzer.Analyse(
		security, hops, parsed.ExtractedURLs, parsed.Attachments, nlp, parsed.Metadata,
	)

	return &analyzer.AnalysisResult{
		Metadata:         parsed.Metadata,
		SecurityChecks:   security,
		RiskScore:        score,
		RiskLevel:        riskLevel,
		Verdict:          verdict,
		Hops:             hops,
		ThreatIndicators: indicators,
		NLPAnalysis:      nlp,
		ExtractedURLs:    parsed.ExtractedURLs,
		Attachments:      parsed.Attachments,
	}, nil
}
