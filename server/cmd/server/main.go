package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"email-threat-forensics/internal/api"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	addr := fmt.Sprintf(":%s", port)
	fmt.Printf("🔍 Email Threat Forensics API running at http://localhost%s\n", addr)
	fmt.Println("   Endpoints:")
	fmt.Println("   GET  /api/v1/health")
	fmt.Println("   GET  /api/v1/samples")
	fmt.Println("   POST /api/v1/analyze  (multipart .eml | JSON {sample_id} | raw EML body)")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
