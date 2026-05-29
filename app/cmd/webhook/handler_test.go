package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testSecret = "marketplace-test-secret"

func post(t *testing.T, body []byte, headerSecret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhook/github-marketplace", bytes.NewReader(body))
	if headerSecret != "" {
		req.Header.Set("X-Hub-Signature-256", sign([]byte(headerSecret), body))
	}
	rec := httptest.NewRecorder()
	handleMarketplace([]byte(testSecret)).ServeHTTP(rec, req)
	return rec
}

func TestHandlerAcceptsPurchasedAction(t *testing.T) {
	body := []byte(`{
		"action": "purchased",
		"effective_date": "2026-05-18T12:00:00Z",
		"sender": {"login": "buyer"},
		"marketplace_purchase": {
			"account": {"login": "acme", "type": "Organization", "id": 42},
			"billing_cycle": "monthly",
			"plan": {"name": "Guardian Pro", "monthly_price_in_cents": 4900, "unit_name": "seat"},
			"unit_count": 5
		}
	}`)
	rec := post(t, body, testSecret)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Errorf("body=%q, want contains ok:true", rec.Body.String())
	}
}

func TestHandlerAcceptsAllRecognisedActions(t *testing.T) {
	actions := []string{"purchased", "cancelled", "changed", "pending_change", "pending_change_cancelled"}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			body := []byte(`{"action":"` + action + `","marketplace_purchase":{"account":{"login":"acme"},"plan":{"name":"p"}}}`)
			rec := post(t, body, testSecret)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 for action %s; body=%s", rec.Code, action, rec.Body.String())
			}
		})
	}
}

func TestHandlerRejectsUnrecognisedAction(t *testing.T) {
	body := []byte(`{"action":"refunded","marketplace_purchase":{"account":{"login":"acme"},"plan":{"name":"p"}}}`)
	rec := post(t, body, testSecret)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandlerRejectsBadSignature(t *testing.T) {
	body := []byte(`{"action":"purchased","marketplace_purchase":{"account":{"login":"acme"},"plan":{"name":"p"}}}`)
	// Sign with the wrong secret to make the digest mismatch under the real secret.
	rec := post(t, body, "the-wrong-secret")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandlerRejectsMalformedSignatureHeader(t *testing.T) {
	body := []byte(`{"action":"purchased","marketplace_purchase":{"account":{"login":"acme"},"plan":{"name":"p"}}}`)
	req := httptest.NewRequest(http.MethodPost, "/webhook/github-marketplace", bytes.NewReader(body))
	// Wrong header format — no "sha256=" prefix.
	req.Header.Set("X-Hub-Signature-256", "deadbeef")
	rec := httptest.NewRecorder()
	handleMarketplace([]byte(testSecret)).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandlerRejectsMissingSignatureHeader(t *testing.T) {
	body := []byte(`{"action":"purchased"}`)
	req := httptest.NewRequest(http.MethodPost, "/webhook/github-marketplace", bytes.NewReader(body))
	// Deliberately no X-Hub-Signature-256 header.
	rec := httptest.NewRecorder()
	handleMarketplace([]byte(testSecret)).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for missing sig; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandlerRejectsInvalidJSON(t *testing.T) {
	body := []byte(`{not valid json`)
	rec := post(t, body, testSecret)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandler500sWhenSecretMissing(t *testing.T) {
	body := []byte(`{"action":"purchased","marketplace_purchase":{"account":{"login":"acme"},"plan":{"name":"p"}}}`)
	req := httptest.NewRequest(http.MethodPost, "/webhook/github-marketplace", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sign([]byte(testSecret), body))
	rec := httptest.NewRecorder()
	handleMarketplace(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for missing secret; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandlerRejectsOversizeBody(t *testing.T) {
	// Build a body just over the 1 MiB cap. JSON validity doesn't matter —
	// the cap should engage during io.ReadAll long before unmarshalling.
	big := make([]byte, payloadMaxBytes+1)
	for i := range big {
		big[i] = 'A'
	}
	req := httptest.NewRequest(http.MethodPost, "/webhook/github-marketplace", bytes.NewReader(big))
	// Sign over the full body so a real cap rejection (not a sig failure)
	// is the only reason this fails. The handler still rejects because
	// io.ReadAll on MaxBytesReader errors before signature verification.
	req.Header.Set("X-Hub-Signature-256", sign([]byte(testSecret), big))
	rec := httptest.NewRecorder()
	handleMarketplace([]byte(testSecret)).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for oversize body; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandlerToleratesUnknownEventFields(t *testing.T) {
	// GitHub may add new fields to the payload over time. The minimal-
	// projection struct must not break on those.
	body := []byte(`{
		"action": "purchased",
		"effective_date": "2026-05-18T12:00:00Z",
		"some_new_top_level_field": "ignore me",
		"marketplace_purchase": {
			"account": {"login": "acme", "future_field": 123},
			"plan": {"name": "Pro"},
			"unit_count": 1
		}
	}`)
	rec := post(t, body, testSecret)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for forward-compatible payload; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRoutesRegisteredOnMux(t *testing.T) {
	// End-to-end mux test: build the same routing table main() builds and
	// hit it via httptest.NewServer so 404s on path/method typos surface.
	mux := http.NewServeMux()
	secret := []byte(testSecret)
	mux.HandleFunc("POST /webhook/github-marketplace", handleMarketplace(secret))
	mux.HandleFunc("GET /health", handleHealth)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// POST happy path
	body := []byte(`{"action":"purchased","marketplace_purchase":{"account":{"login":"acme"},"plan":{"name":"p"}}}`)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/webhook/github-marketplace", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Hub-Signature-256", sign(secret, body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /webhook/github-marketplace: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		got, _ := io.ReadAll(resp.Body)
		t.Errorf("POST /webhook status=%d, want 200; body=%s", resp.StatusCode, got)
	}

	// GET /health
	hresp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		t.Errorf("GET /health status=%d, want 200", hresp.StatusCode)
	}

	// Wrong method on webhook returns 405 from Go 1.22+ method-prefixed mux.
	gresp, err := http.Get(srv.URL + "/webhook/github-marketplace")
	if err != nil {
		t.Fatalf("GET /webhook: %v", err)
	}
	defer gresp.Body.Close()
	if gresp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /webhook status=%d, want 405", gresp.StatusCode)
	}
}

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q, want application/json", got)
	}
	if got, _ := io.ReadAll(rec.Body); !strings.Contains(string(got), `"status":"ok"`) {
		t.Errorf("body=%q, want contains status:ok", got)
	}
}
