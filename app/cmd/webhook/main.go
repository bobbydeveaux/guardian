// Package main — Guardian GitHub Marketplace billing webhook.
//
// Single-binary stdlib-only HTTP server that receives marketplace_purchase
// events when a customer upgrades, downgrades, or cancels Guardian on the
// GitHub Marketplace. Designed for Cloud Run via StackRamp.
//
// Routes:
//   POST /webhook/github-marketplace   verify X-Hub-Signature-256, log event
//   GET  /health                       liveness probe
//
// Env vars:
//   GITHUB_WEBHOOK_SECRET   HMAC-SHA256 shared secret configured in the
//                           Marketplace listing. Required — server returns
//                           500 on every event until set.
//   PORT                    Listen port. Default 8080 (Cloud Run convention).
package main

import (
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	secret := []byte(os.Getenv("GITHUB_WEBHOOK_SECRET"))
	if len(secret) == 0 {
		log.Printf("marketplace: GITHUB_WEBHOOK_SECRET is not set — webhook will 500 on every event until configured")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook/github-marketplace", handleMarketplace(secret))
	mux.HandleFunc("GET /health", handleHealth)

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("marketplace: listening on :%s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("marketplace: server error: %v", err)
	}
}
