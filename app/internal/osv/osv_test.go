package osv

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withAPIURL temporarily redirects the package's osvAPI variable. Tests that
// mutate it must not run in parallel.
func withAPIURL(t *testing.T, url string) {
	t.Helper()
	prev := osvAPI
	osvAPI = url
	t.Cleanup(func() { osvAPI = prev })
}

func TestQueryPackageHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content-type = %q, want application/json", got)
		}
		body, _ := io.ReadAll(r.Body)
		var in osvRequest
		if err := json.Unmarshal(body, &in); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if in.Package.Name != "lodash" || in.Package.Ecosystem != "npm" || in.Version != "4.17.20" {
			t.Errorf("payload = %+v, missing fields", in)
		}
		_, _ = w.Write([]byte(`{"vulns":[
			{"id":"GHSA-xxxx-yyyy","summary":"Prototype Pollution","database_specific":{"severity":"HIGH"}},
			{"id":"CVE-2021-0000","summary":"Path Traversal","severity":[{"type":"CVSS","score":"critical"}]},
			{"id":"GHSA-noseverity","summary":"no severity"}
		]}`))
	}))
	t.Cleanup(srv.Close)
	withAPIURL(t, srv.URL)

	findings, err := QueryPackage("npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("QueryPackage: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(findings))
	}
	if findings[0].Severity != "HIGH" {
		t.Errorf("findings[0].Severity = %q, want HIGH", findings[0].Severity)
	}
	if findings[1].Severity != "CRITICAL" {
		t.Errorf("findings[1].Severity = %q, want CRITICAL", findings[1].Severity)
	}
	if findings[2].Severity != "UNKNOWN" {
		t.Errorf("findings[2].Severity = %q, want UNKNOWN", findings[2].Severity)
	}
	for _, f := range findings {
		if f.Package != "lodash" || f.Ecosystem != "npm" || f.Version != "4.17.20" {
			t.Errorf("finding identity wrong: %+v", f)
		}
	}
}

func TestQueryPackageNoVulns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
	t.Cleanup(srv.Close)
	withAPIURL(t, srv.URL)

	findings, err := QueryPackage("Go", "github.com/x/y", "1.0.0")
	if err != nil {
		t.Fatalf("QueryPackage: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}
}

func TestQueryPackageNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server gone", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	withAPIURL(t, srv.URL)

	_, err := QueryPackage("npm", "x", "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v, want one containing 500", err)
	}
}

func TestQueryPackageNetworkError(t *testing.T) {
	// Closed server URL returns a connection refused / network error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.Close()
	withAPIURL(t, srv.URL)

	_, err := QueryPackage("npm", "x", "1.0.0")
	if err == nil {
		t.Fatal("expected network error")
	}
	if !strings.Contains(err.Error(), "OSV API request failed") {
		t.Errorf("err = %v, want wrapping OSV API request failed", err)
	}
}

func TestQueryPackageBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	t.Cleanup(srv.Close)
	withAPIURL(t, srv.URL)

	_, err := QueryPackage("npm", "x", "1.0.0")
	if err == nil {
		t.Fatal("expected JSON decode error")
	}
}

func TestScanPackagesAggregatesAndSkipsErrors(t *testing.T) {
	// Server returns a vuln for lodash and a 500 for express. ScanPackages
	// must return lodash findings and silently skip the express failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "lodash") {
			_, _ = w.Write([]byte(`{"vulns":[{"id":"GHSA-1","summary":"x","database_specific":{"severity":"LOW"}}]}`))
			return
		}
		if strings.Contains(string(body), "express") {
			http.Error(w, "bad", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
	t.Cleanup(srv.Close)
	withAPIURL(t, srv.URL)

	all, err := ScanPackages([]Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
		{Ecosystem: "npm", Name: "express", Version: "4.0.0"},
		{Ecosystem: "npm", Name: "safe", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("ScanPackages: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("findings = %d, want 1 (express skipped, safe empty)", len(all))
	}
	if all[0].Package != "lodash" || all[0].Severity != "LOW" {
		t.Errorf("finding = %+v, want lodash/LOW", all[0])
	}
}

func TestScanPackagesEmpty(t *testing.T) {
	findings, err := ScanPackages(nil)
	if err != nil {
		t.Fatalf("ScanPackages(nil): %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}
}
