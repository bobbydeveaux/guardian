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

func TestIgnoreVariableInterpolation(t *testing.T) {
	// Env passthrough / templating as the value is NOT a hardcoded secret.
	clean := []string{
		`MT5_PASSWORD="${MT5_PASSWORD:-}"`,           // shell default expansion
		`password: "${DB_PASSWORD}"`,                 // docker-compose passthrough
		`PASSWORD="$DB_PASSWORD"`,                    // bare shell var
		`password: "{{ .Values.dbPassword }}"`,       // helm/go template
		`export PGPASSWORD="${PGPASSWORD:-default}"`, // shell with default
	}
	for _, line := range clean {
		if findings := ScanContent("docker/entrypoint.sh", line); len(findings) > 0 {
			t.Errorf("interpolation flagged as secret: %q → %+v", line, findings)
		}
	}
	// ...but a literal password beside similar shapes must still be caught.
	dirty := `password = "hunter2hunter2"`
	if findings := ScanContent("config.py", dirty); len(findings) == 0 {
		t.Errorf("literal password missed: %q", dirty)
	}
}
