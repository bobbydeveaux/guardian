// Package main — Guardian GitHub Marketplace billing webhook.
//
// handler.go contains the HTTP handler for POST /webhook/github-marketplace
// and the minimal-projection event struct.
package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
)

// payloadMaxBytes caps the size of a webhook body we will read. GitHub
// Marketplace events are typically a few KB. 1 MiB is well over the
// documented maximum and prevents memory abuse from a misrouted client.
const payloadMaxBytes = 1 << 20

// marketplaceEvent projects only the fields the handler needs to log.
// Unknown GitHub fields are tolerated (DisallowUnknownFields is NOT set)
// so an upstream payload change does not break the gate at signature
// verification time.
type marketplaceEvent struct {
	Action              string `json:"action"`
	EffectiveDate       string `json:"effective_date"`
	Sender              sender `json:"sender"`
	MarketplacePurchase purchase `json:"marketplace_purchase"`
}

type sender struct {
	Login string `json:"login"`
}

type purchase struct {
	Account      account `json:"account"`
	BillingCycle string  `json:"billing_cycle"`
	Plan         plan    `json:"plan"`
	UnitCount    int     `json:"unit_count"`
}

type account struct {
	Login string `json:"login"`
	Type  string `json:"type"`
	ID    int64  `json:"id"`
}

type plan struct {
	Name                string `json:"name"`
	MonthlyPriceInCents int64  `json:"monthly_price_in_cents"`
	UnitName            string `json:"unit_name"`
}

// recognisedActions is the set of marketplace_purchase action values the
// handler accepts. GitHub documents:
//   purchased, cancelled, changed, pending_change, pending_change_cancelled
// Any other action returns 422 so misconfigurations surface loudly.
var recognisedActions = map[string]struct{}{
	"purchased":                {},
	"cancelled":                {},
	"changed":                  {},
	"pending_change":           {},
	"pending_change_cancelled": {},
}

// handleMarketplace is the POST /webhook/github-marketplace handler.
//
// Behaviour:
//   - Reads the body (capped at payloadMaxBytes).
//   - Verifies X-Hub-Signature-256 against secret.
//   - Parses the body as marketplaceEvent (minimal projection).
//   - Logs one structured line per accepted action and returns 200.
//   - Returns 500 if secret is empty (loud failure).
//   - Returns 400 on signature failure, malformed signature, or unread body.
//   - Returns 422 on unrecognised action.
func handleMarketplace(secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(secret) == 0 {
			log.Printf("marketplace: GITHUB_WEBHOOK_SECRET is not set")
			http.Error(w, "webhook secret not configured", http.StatusInternalServerError)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, payloadMaxBytes))
		if err != nil {
			log.Printf("marketplace: read body: %v", err)
			http.Error(w, "could not read request body", http.StatusBadRequest)
			return
		}
		sigHeader := r.Header.Get("X-Hub-Signature-256")
		if err := verifySignature(secret, body, sigHeader); err != nil {
			switch {
			case errors.Is(err, errMalformedSignature):
				log.Printf("marketplace: malformed signature header")
				http.Error(w, "malformed X-Hub-Signature-256", http.StatusBadRequest)
			case errors.Is(err, errBadSignature):
				log.Printf("marketplace: signature verification failed")
				http.Error(w, "signature verification failed", http.StatusBadRequest)
			default:
				log.Printf("marketplace: signature error: %v", err)
				http.Error(w, "signature error", http.StatusBadRequest)
			}
			return
		}
		var event marketplaceEvent
		if err := json.Unmarshal(body, &event); err != nil {
			log.Printf("marketplace: parse body: %v", err)
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if _, ok := recognisedActions[event.Action]; !ok {
			log.Printf("marketplace: unrecognised action=%q (event ignored)", event.Action)
			http.Error(w, "unrecognised marketplace_purchase action", http.StatusUnprocessableEntity)
			return
		}
		log.Printf(
			"marketplace: action=%s account=%s account_type=%s plan=%q units=%d billing_cycle=%s effective_date=%s sender=%s",
			event.Action,
			event.MarketplacePurchase.Account.Login,
			event.MarketplacePurchase.Account.Type,
			event.MarketplacePurchase.Plan.Name,
			event.MarketplacePurchase.UnitCount,
			event.MarketplacePurchase.BillingCycle,
			event.EffectiveDate,
			event.Sender.Login,
		)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
}

// handleHealth is the GET /health liveness endpoint. Cloud Run uses this
// for startup probes; returning 200 with a tiny body keeps the path cheap.
func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
