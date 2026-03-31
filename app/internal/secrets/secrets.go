// Package secrets detects hardcoded credentials and secrets in staged file content.
package secrets

import (
	"regexp"
	"strings"
)

// Finding represents a detected secret.
type Finding struct {
	File    string
	Line    int
	Rule    string
	Match   string // redacted snippet
	Entropy float64
}

// rule is a compiled detection rule.
type rule struct {
	Name    string
	Pattern *regexp.Regexp
}

var rules = []rule{
	{Name: "AWS Access Key", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{Name: "AWS Secret Key", Pattern: regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]`)},
	{Name: "Generic API Key", Pattern: regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[0-9a-zA-Z\-_]{20,}['\"]?`)},
	{Name: "Private Key Header", Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{Name: "Generic Password", Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'"]{8,}['"]`)},
	{Name: "Generic Secret", Pattern: regexp.MustCompile(`(?i)(secret|token)\s*[:=]\s*['\"][0-9a-zA-Z\-_\.]{16,}['\"]`)},
	{Name: "GitHub Token", Pattern: regexp.MustCompile(`gh[pousr]_[0-9a-zA-Z]{36}`)},
	{Name: "Anthropic API Key", Pattern: regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-_]{20,}`)},
	{Name: "OpenAI API Key", Pattern: regexp.MustCompile(`sk-[a-zA-Z0-9]{48}`)},
	{Name: "Slack Token", Pattern: regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]+`)},
	{Name: "Stripe Key", Pattern: regexp.MustCompile(`[rs]k_(live|test)_[0-9a-zA-Z]{24,}`)},
	{Name: "Google API Key", Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`)},
	{Name: "JWT Token", Pattern: regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`)},
	{Name: "Connection String", Pattern: regexp.MustCompile(`(?i)(mongodb|mysql|postgres|redis|amqp)://[^'">\s]{10,}`)},
	{Name: "Basic Auth in URL", Pattern: regexp.MustCompile(`https?://[^:'">\s]+:[^@'">\s]{4,}@[^\s'"]+`)},
}

// ignorePatterns are lines to skip (test fixtures, examples, etc.)
var ignorePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)example`),
	regexp.MustCompile(`(?i)placeholder`),
	regexp.MustCompile(`(?i)your.{0,5}key.{0,5}here`),
	regexp.MustCompile(`(?i)fake|dummy|mock|stub`),
	regexp.MustCompile(`\bxxxx+\b`),
	regexp.MustCompile(`<YOUR_`),
}

// ScanContent scans the content of a single file for secrets.
func ScanContent(filename, content string) []Finding {
	var findings []Finding
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		// Skip comment-heavy or obviously templated lines
		if shouldIgnore(line) {
			continue
		}
		for _, r := range rules {
			if m := r.Pattern.FindString(line); m != "" {
				findings = append(findings, Finding{
					File:  filename,
					Line:  i + 1,
					Rule:  r.Name,
					Match: redact(m),
				})
			}
		}
	}
	return findings
}

// ScanFiles scans a map of filename→content for secrets.
func ScanFiles(files map[string]string) []Finding {
	var all []Finding
	for name, content := range files {
		all = append(all, ScanContent(name, content)...)
	}
	return all
}

// shouldIgnore returns true if the line looks like a template/example.
func shouldIgnore(line string) bool {
	for _, p := range ignorePatterns {
		if p.MatchString(line) {
			return true
		}
	}
	return false
}

// redact replaces the middle portion of a match with asterisks.
func redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	keep := 4
	return s[:keep] + strings.Repeat("*", len(s)-keep*2) + s[len(s)-keep:]
}
