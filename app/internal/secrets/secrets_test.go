package secrets

import (
	"testing"
)

func TestScanContent(t *testing.T) {
	content := `
api_key = "sk-ant-api03-FAKE_KEY_FOR_TESTING_1234567890abcdef"
password = "supersecret123"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
`
	findings := ScanContent("config.py", content)
	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}
	t.Logf("Found %d secret(s):", len(findings))
	for _, f := range findings {
		t.Logf("  Line %d [%s]: %s", f.Line, f.Rule, f.Match)
	}
}

func TestIgnorePlaceholders(t *testing.T) {
	content := `api_key = "your_api_key_here_example_placeholder"`
	findings := ScanContent("config.py", content)
	if len(findings) > 0 {
		t.Errorf("expected no findings for placeholder, got %d", len(findings))
	}
}
