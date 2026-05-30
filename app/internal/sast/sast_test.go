package sast

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// withAPIKey sets ANTHROPIC_API_KEY for the duration of the test and restores
// the prior value on cleanup.
func withAPIKey(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv("ANTHROPIC_API_KEY")
	if err := os.Setenv("ANTHROPIC_API_KEY", key); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("ANTHROPIC_API_KEY", prev)
		} else {
			_ = os.Unsetenv("ANTHROPIC_API_KEY")
		}
	})
}

// withAPIURL temporarily redirects the package's anthropicAPI variable. Tests
// that mutate it must not run in parallel.
func withAPIURL(t *testing.T, url string) {
	t.Helper()
	prev := anthropicAPI
	anthropicAPI = url
	t.Cleanup(func() { anthropicAPI = prev })
}

// unsetAPIKey clears the env var for the duration of the test.
func unsetAPIKey(t *testing.T) {
	t.Helper()
	prev, had := os.LookupEnv("ANTHROPIC_API_KEY")
	_ = os.Unsetenv("ANTHROPIC_API_KEY")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("ANTHROPIC_API_KEY", prev)
		}
	})
}

func TestAnalyseDiffNoKey(t *testing.T) {
	unsetAPIKey(t)
	_, err := AnalyseDiff("some diff")
	if err == nil {
		t.Fatal("expected error when ANTHROPIC_API_KEY is unset")
	}
	if !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") {
		t.Errorf("expected error to mention ANTHROPIC_API_KEY, got %q", err)
	}
}

func TestAnalyseFilesNoKey(t *testing.T) {
	unsetAPIKey(t)
	// callClaude is only invoked when entries are non-empty; ensure we have one.
	_, err := AnalyseFiles(map[string]string{"x.go": "package main"})
	if err == nil {
		t.Fatal("expected error when ANTHROPIC_API_KEY is unset")
	}
}

func TestAnalyseFilesEmptyInput(t *testing.T) {
	unsetAPIKey(t) // even with no key, an empty input must short-circuit
	findings, err := AnalyseFiles(map[string]string{})
	if err != nil {
		t.Fatalf("AnalyseFiles empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %v", findings)
	}
}

// fakeServer returns an httptest.Server that captures requests and replies
// with the supplied Claude-shaped JSON envelope around `bodyText`.
func fakeServer(t *testing.T, bodyText string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("x-api-key") == "" {
			http.Error(w, "missing x-api-key", http.StatusUnauthorized)
			return
		}
		// Drain the body so the client sees a clean cycle.
		_, _ = io.Copy(io.Discard, r.Body)

		envelope := map[string]any{
			"content": []map[string]string{
				{"type": "text", "text": bodyText},
			},
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAnalyseDiffSuccess(t *testing.T) {
	finding := `[{"file":"x.go","line":1,"severity":"HIGH","category":"SQL Injection","message":"hi","snippet":"abc"}]`
	srv := fakeServer(t, finding, http.StatusOK)
	withAPIKey(t, "test-key")
	withAPIURL(t, srv.URL)

	findings, err := AnalyseDiff("some diff")
	if err != nil {
		t.Fatalf("AnalyseDiff: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "HIGH" || findings[0].Category != "SQL Injection" {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
}

func TestAnalyseDiffSuccessFenced(t *testing.T) {
	// The function strips ```json ... ``` fences. Verify that path.
	fenced := "```json\n[]\n```"
	srv := fakeServer(t, fenced, http.StatusOK)
	withAPIKey(t, "test-key")
	withAPIURL(t, srv.URL)

	findings, err := AnalyseDiff("d")
	if err != nil {
		t.Fatalf("AnalyseDiff fenced: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %v", findings)
	}
}

func TestAnalyseDiffTruncates(t *testing.T) {
	// Provide a long diff to exercise the >12000 char truncation path.
	long := strings.Repeat("a", 13000)
	srv := fakeServer(t, "[]", http.StatusOK)
	withAPIKey(t, "test-key")
	withAPIURL(t, srv.URL)

	if _, err := AnalyseDiff(long); err != nil {
		t.Fatalf("AnalyseDiff truncated: %v", err)
	}
}

func TestAnalyseDiffHTTPError(t *testing.T) {
	srv := fakeServer(t, "ignored", http.StatusInternalServerError)
	withAPIKey(t, "test-key")
	withAPIURL(t, srv.URL)

	if _, err := AnalyseDiff("d"); err == nil {
		t.Fatal("expected error on non-200 response")
	}
}

func TestAnalyseDiffBadJSON(t *testing.T) {
	srv := fakeServer(t, "not valid json", http.StatusOK)
	withAPIKey(t, "test-key")
	withAPIURL(t, srv.URL)

	if _, err := AnalyseDiff("d"); err == nil {
		t.Fatal("expected error on unparseable Claude response")
	}
}

func TestAnalyseFilesBatching(t *testing.T) {
	// Create enough fake files to force at least one batch flush.
	files := make(map[string]string, 5)
	big := strings.Repeat("x", 4000)
	for i := 0; i < 5; i++ {
		files[strings.Repeat("a", i+1)+".go"] = big
	}
	srv := fakeServer(t, "[]", http.StatusOK)
	withAPIKey(t, "test-key")
	withAPIURL(t, srv.URL)

	findings, err := AnalyseFiles(files)
	if err != nil {
		t.Fatalf("AnalyseFiles: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %v", findings)
	}
}
