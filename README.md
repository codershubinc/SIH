# SIH26106 – Email Threat Forensics MVP

AI-Powered Email Threat Detection & Forensic Intelligence Platform.

## Project Structure
```
.
├── server/                        ← Go 1.22 backend API
│   ├── cmd/
│   │   └── server/
│   │       └── main.go            ← Entrypoint
│   └── internal/
│       ├── api/
│       │   ├── handlers.go        ← Route handlers
│       │   └── routes.go          ← Route registration
│       ├── auth/
│       │   └── verifier.go        ← SPF/DKIM/DMARC evaluator
│       ├── geoip/
│       │   └── geoip.go           ← GeoIP resolver (offline DB + ip-api.com fallback)
│       ├── helpers/
│       │   └── http.go            ← JSON response, CORS, Logger middleware
│       ├── models/
│       │   └── models.go          ← All shared types
│       ├── parser/
│       │   ├── eml.go             ← RFC 5322 parser (body, attachments, URLs)
│       │   └── hops.go            ← Received: header hop extractor
│       ├── samples/
│       │   ├── fixtures.go        ← Sample registry + embedded FS
│       │   ├── phishing_paypal.eml
│       │   ├── bec_wire_transfer.eml
│       │   ├── malware_invoice.eml
│       │   ├── crypto_scam.eml
│       │   └── legitimate_google.eml
│       └── threat/
│           └── engine.go          ← NLP heuristics + risk scorer + verdict engine
├── frontend/                      ← Bun static server + Vanilla JS UI
│   ├── index.ts                   ← Bun HTTP server (port 5173)
│   └── public/
│       ├── index.html             ← Dark SOC dashboard
│       ├── css/style.css
│       └── js/
│           ├── app.js             ← Upload, sample loading, API integration
│           ├── map.js             ← Leaflet.js hop routing map
│           └── ui.js              ← All render functions
└── README.md
```

## Running

### Backend (Go API – port 8080)
```bash
cd server
go run ./cmd/server
```

### Frontend (Bun static server – port 5173)
```bash
cd frontend
bun run serve
```

Open http://localhost:5173 in your browser.

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | Service health check |
| GET | `/api/v1/samples` | List pre-loaded sample fixtures |
| POST | `/api/v1/analyze` | Analyse an email |

### POST /api/v1/analyze

Accepts three input modes:

1. **Multipart file upload**: `Content-Type: multipart/form-data`, field name `file`
2. **Sample ID**: `{"sample_id": "phishing_paypal"}`
3. **Raw EML content**: `{"raw_content": "From: ..."}`

### Sample IDs
- `phishing_paypal` – PayPal credential phishing with Tor origin
- `bec_wire_transfer` – BEC CEO wire transfer attack
- `malware_invoice` – Invoice with .iso malware attachment
- `crypto_scam` – Cryptocurrency advance-fee fraud
- `legitimate_google` – Clean Google security alert (control)
