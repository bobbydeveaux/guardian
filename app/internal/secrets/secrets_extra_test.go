package secrets

import (
	"strings"
	"testing"
)

func TestScanFilesMultiple(t *testing.T) {
	files := map[string]string{
		"config.py":      `api_key = "sk-ant-api03-realkey1234567890abcdef"`,
		"main.go":        `password = "supersecure123"`,
		"README.md":      "no secrets here",
		"some_test.go":   `api_key = "sk-ant-this-should-be-ignored-by-file-filter"`,
		"fixtures/x.txt": `password = "ignoredbydir12345"`,
	}
	findings := ScanFiles(files)
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}
	// Verify ignored files are not reported.
	for _, f := range findings {
		if strings.Contains(f.File, "_test.go") {
			t.Errorf("unexpectedly scanned test file: %v", f)
		}
		if strings.Contains(f.File, "fixtures/") {
			t.Errorf("unexpectedly scanned fixtures dir: %v", f)
		}
	}
}

func TestShouldIgnoreFile(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"foo_test.go", true},
		{"test_foo.py", true},
		{"demo_vuln_sample.js", true},
		{"fixtures/data.json", true},
		{"app/testdata/file.txt", true},
		{"main.go", false},
		{"src/app.py", false},
	}
	for _, c := range cases {
		if got := shouldIgnoreFile(c.name); got != c.want {
			t.Errorf("shouldIgnoreFile(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestShouldIgnore(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"this is just an example", true},
		{"placeholder value here", true},
		{"YOUR_API_KEY_HERE example", true},
		{"this is a fake password", true},
		{"<YOUR_KEY>", true},
		{"<link href='https://fonts.googleapis.com/css?family=Roboto'>", true},
		{"actual api key: sk-real-thing", false},
		{"xxxx test for x markers", true},
	}
	for _, c := range cases {
		if got := shouldIgnore(c.line); got != c.want {
			t.Errorf("shouldIgnore(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestRedact(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"short", "*****"},                       // length <=8 fully masked
		{"12345678", "********"},                 // length =8 fully masked
		{"AKIAIOSFODNN7EXAMPLE", "AKIA************MPLE"}, // 20 chars, keep 4 each end
	}
	for _, c := range cases {
		if got := redact(c.in); got != c.want {
			t.Errorf("redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestScanContentRules(t *testing.T) {
	// One sample per major rule type to confirm regex coverage.
	cases := []struct {
		name    string
		content string
		ruleSub string // substring expected in the matched rule name
	}{
		{"github token", "token = ghp_" + strings.Repeat("a", 36), "GitHub Token"},
		{"openai key", "key = sk-" + strings.Repeat("a", 48), "OpenAI"},
		{"slack token", "tok = xoxb-1-asdfasdfasdf", "Slack"},
		{"stripe key", "k = sk_live_" + strings.Repeat("a", 24), "Stripe"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----", "Private Key"},
		{"jwt", "tok = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "JWT"},
		{"mongo conn", "u = mongodb://user:passw@host:27017/db", "Connection String"},
		{"basic auth", "u = https://user:secretvalue@host.local/p", "Basic Auth"},
	}
	for _, c := range cases {
		findings := ScanContent("test.go", c.content)
		if len(findings) == 0 {
			t.Errorf("%s: expected findings, got none", c.name)
			continue
		}
		matched := false
		for _, f := range findings {
			if strings.Contains(f.Rule, c.ruleSub) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("%s: expected rule containing %q, got %+v", c.name, c.ruleSub, findings)
		}
	}
}

func TestScanContentNoMatch(t *testing.T) {
	if findings := ScanContent("a.txt", "nothing interesting here\n"); len(findings) != 0 {
		t.Errorf("expected no findings, got %v", findings)
	}
}
