package api

import (
	"net/http"
)

// RegisterRoutes wires all API routes onto the given mux
func RegisterRoutes(mux *http.ServeMux) {
	// Wrap each route with CORS + Logger middleware
	wrap := func(h http.HandlerFunc) http.Handler {
		return Logger(CORS(h))
	}

	mux.Handle("GET /api/v1/health", wrap(HealthHandler))
	mux.Handle("GET /api/v1/samples", wrap(SamplesHandler))
	mux.Handle("POST /api/v1/analyze", wrap(AnalyzeHandler))

	// OPTIONS preflight for all /api routes
	mux.Handle("OPTIONS /api/v1/analyze", wrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}
