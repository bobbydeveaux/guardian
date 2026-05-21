// Package sast uses Claude to perform lightweight static analysis on staged diffs.
package sast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const anthropicAPI = "https://api.anthropic.com/v1/messages"

// Finding is a code-level security issue identified by Claude.
type Finding struct {
	File     string
	Line     int
	Severity string // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Category string // e.g. "SQL Injection", "XSS", "Path Traversal"
	Message  string
	Snippet  string
}

type anthropicRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system"`
	Messages  []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

const systemPrompt = `You are a security code reviewer. Analyse the provided git diff for security vulnerabilities.

Focus on:
- Injection flaws (SQL, command, LDAP, XPath)
- Cross-site scripting (XSS)
- Insecure direct object references
- Sensitive data exposure (credentials, PII logged, unencrypted storage)
- Broken authentication / missing auth checks
- Insecure deserialization
- Using components with known vulnerabilities
- Path traversal / LFI
- SSRF (Server-Side Request Forgery)
- Race conditions
- Insecure cryptography (MD5, SHA1 for passwords, ECB mode, etc.)
- Missing input validation on user-supplied data

Return a JSON array of findings. Each finding must have these exact fields:
- file: string (filename from the diff)
- line: number (approximate line number in the NEW file, or 0 if unknown)
- severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
- category: short category name (e.g. "SQL Injection")
- message: clear explanation of the issue and how to fix it
- snippet: the relevant code snippet (max 120 chars)

If there are no issues, return an empty array [].
Return ONLY the JSON array, no prose.`

// AnalyseFiles sends batches of source files to Claude for full-codebase analysis.
// Files are grouped into ~10 KB batches to stay within token limits.
func AnalyseFiles(files map[string]string) ([]Finding, error) {
	const batchSize = 10000

	// Build ordered batch slices
	type fileEntry struct{ name, content string }
	var entries []fileEntry
	for name, content := range files {
		entries = append(entries, fileEntry{name, content})
	}

	var all []Finding
	var buf strings.Builder
	var batchFiles []string

	flush := func() error {
		if buf.Len() == 0 {
			return nil
		}
		findings, err := callClaude(buf.String(), "file contents")
		if err != nil {
			return err
		}
		all = append(all, findings...)
		buf.Reset()
		batchFiles = batchFiles[:0]
		return nil
	}

	for _, e := range entries {
		chunk := fmt.Sprintf("=== %s ===\n%s\n\n", e.name, e.content)
		if buf.Len()+len(chunk) > batchSize && buf.Len() > 0 {
			if err := flush(); err != nil {
				return all, err
			}
		}
		buf.WriteString(chunk)
		batchFiles = append(batchFiles, e.name)
	}
	if err := flush(); err != nil {
		return all, err
	}
	return all, nil
}

const fullScanSystemPrompt = `You are a security code reviewer. Analyse the provided source files for security vulnerabilities.

Focus on:
- Injection flaws (SQL, command, LDAP, XPath)
- Cross-site scripting (XSS)
- Insecure direct object references
- Sensitive data exposure (credentials, PII logged, unencrypted storage)
- Broken authentication / missing auth checks
- Insecure deserialization
- Path traversal / LFI
- SSRF (Server-Side Request Forgery)
- Race conditions
- Insecure cryptography (MD5, SHA1 for passwords, ECB mode, etc.)
- Missing input validation on user-supplied data

Return a JSON array of findings. Each finding must have these exact fields:
- file: string (exact filename as shown in the === header ===)
- line: number (approximate line number, or 0 if unknown)
- severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
- category: short category name (e.g. "SQL Injection")
- message: clear explanation of the issue and how to fix it
- snippet: the relevant code snippet (max 120 chars)

If there are no issues, return an empty array [].
Return ONLY the JSON array, no prose.`

func callClaude(content, contentType string) ([]Finding, error) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	var sysPrompt, userMsg string
	if contentType == "file contents" {
		sysPrompt = fullScanSystemPrompt
		userMsg = fmt.Sprintf("Analyse these source files for security issues:\n\n%s", content)
	} else {
		sysPrompt = systemPrompt
		userMsg = fmt.Sprintf("Analyse this git diff for security issues:\n\n```diff\n%s\n```", content)
	}

	reqBody := anthropicRequest{
		Model:     "claude-haiku-4-5-20251001",
		MaxTokens: 2048,
		System:    sysPrompt,
		Messages:  []message{{Role: "user", Content: userMsg}},
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", anthropicAPI, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Anthropic API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Anthropic API returned %d", resp.StatusCode)
	}

	var ar anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return nil, err
	}
	if len(ar.Content) == 0 {
		return nil, nil
	}

	raw := strings.TrimSpace(ar.Content[0].Text)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	var findings []Finding
	if err := json.Unmarshal([]byte(raw), &findings); err != nil {
		return nil, fmt.Errorf("could not parse Claude response: %w\nraw: %s", err, raw)
	}
	return findings, nil
}

// AnalyseDiff sends the staged diff to Claude and returns security findings.
func AnalyseDiff(diff string) ([]Finding, error) {
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}
	if len(diff) > 12000 {
		diff = diff[:12000] + "\n... (diff truncated)"
	}
	return callClaude(diff, "diff")
}
