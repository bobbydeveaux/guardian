// Package osv queries the OSV vulnerability database (https://api.osv.dev).
package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const osvAPI = "https://api.osv.dev/v1/query"

// Finding is a matched vulnerability for a package.
type Finding struct {
	Ecosystem string
	Package   string
	Version   string
	ID        string // e.g. CVE-2023-XXXX or GHSA-…
	Summary   string
	Severity  string // CRITICAL, HIGH, MODERATE, LOW
}

type osvRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version,omitempty"`
}

type osvResponse struct {
	Vulns []struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	} `json:"vulns"`
}

// QueryPackage queries OSV for a single package/version.
func QueryPackage(ecosystem, name, version string) ([]Finding, error) {
	body := osvRequest{}
	body.Package.Name = name
	body.Package.Ecosystem = ecosystem
	body.Version = version

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(osvAPI, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("OSV API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OSV API returned %d", resp.StatusCode)
	}

	var result osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, v := range result.Vulns {
		sev := v.DatabaseSpecific.Severity
		if sev == "" && len(v.Severity) > 0 {
			sev = v.Severity[0].Score
		}
		if sev == "" {
			sev = "UNKNOWN"
		}
		findings = append(findings, Finding{
			Ecosystem: ecosystem,
			Package:   name,
			Version:   version,
			ID:        v.ID,
			Summary:   v.Summary,
			Severity:  strings.ToUpper(sev),
		})
	}
	return findings, nil
}

// Package represents a dependency to check.
type Package struct {
	Ecosystem string
	Name      string
	Version   string
}

// ScanPackages checks a list of packages against OSV and returns all findings.
func ScanPackages(packages []Package) ([]Finding, error) {
	var all []Finding
	for _, pkg := range packages {
		findings, err := QueryPackage(pkg.Ecosystem, pkg.Name, pkg.Version)
		if err != nil {
			// Non-fatal: skip this package and continue
			continue
		}
		all = append(all, findings...)
	}
	return all, nil
}
