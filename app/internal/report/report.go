// Package report formats scan results for terminal output.
package report

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/bobbydeveaux/guardian/app/internal/osv"
	"github.com/bobbydeveaux/guardian/app/internal/sast"
	"github.com/bobbydeveaux/guardian/app/internal/secrets"
)

var (
	bold      = color.New(color.Bold)
	critical  = color.New(color.FgRed, color.Bold)
	high      = color.New(color.FgRed)
	medium    = color.New(color.FgYellow)
	low       = color.New(color.FgCyan)
	info      = color.New(color.FgWhite)
	green     = color.New(color.FgGreen, color.Bold)
	dimmed    = color.New(color.FgWhite, color.Faint)
	fileColor = color.New(color.FgMagenta)
)

// Results holds all scan output.
type Results struct {
	StagedFiles    []string
	OSVFindings    []osv.Finding
	SecretFindings []secrets.Finding
	SASTFindings   []sast.Finding
	SASTSkipped    bool
	SASTError      string
	FullScan       bool
}

// severityPrinter returns a colour printer for a severity string.
func severityPrinter(sev string) *color.Color {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return critical
	case "HIGH":
		return high
	case "MEDIUM", "MODERATE":
		return medium
	case "LOW":
		return low
	default:
		return info
	}
}

// severityOrder maps severity to a sort weight (lower = worse).
func severityOrder(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM", "MODERATE":
		return 2
	case "LOW":
		return 3
	default:
		return 4
	}
}

// Print writes the full report to stdout.
func Print(r Results) {
	fmt.Println()
	bold.Println("╔══════════════════════════════════════════════╗")
	bold.Println("║         Guardian — Pre-commit Security Scan  ║")
	bold.Println("╚══════════════════════════════════════════════╝")
	fmt.Println()

	// Scanned files summary
	if r.FullScan {
		dimmed.Printf("  Scanned %d file(s) [full codebase]\n\n", len(r.StagedFiles))
	} else {
		dimmed.Printf("  Scanned %d staged file(s)\n\n", len(r.StagedFiles))
	}

	// ── OSV / Dependency vulns ─────────────────────────────────────────────
	bold.Println("  📦  Dependency Vulnerabilities (OSV)")
	if len(r.OSVFindings) == 0 {
		green.Println("      ✓  No known CVEs found")
	} else {
		for _, f := range r.OSVFindings {
			p := severityPrinter(f.Severity)
			p.Printf("      [%s]  %s@%s\n", f.Severity, f.Package, f.Version)
			fmt.Printf("             %s — %s\n", dimmed.Sprint(f.ID), f.Summary)
		}
	}
	fmt.Println()

	// ── Secrets ───────────────────────────────────────────────────────────
	bold.Println("  🔑  Secrets & Credentials")
	if len(r.SecretFindings) == 0 {
		green.Println("      ✓  No secrets detected")
	} else {
		for _, f := range r.SecretFindings {
			critical.Printf("      [CRITICAL]  %s (line %d)\n", f.Rule, f.Line)
			fmt.Printf("             File: %s\n", fileColor.Sprint(f.File))
			fmt.Printf("             Match: %s\n", dimmed.Sprint(f.Match))
		}
	}
	fmt.Println()

	// ── SAST ──────────────────────────────────────────────────────────────
	bold.Println("  🧠  Code Security Analysis (Claude AI)")
	switch {
	case r.SASTSkipped:
		dimmed.Println("      ⊘  Skipped (no diff / ANTHROPIC_API_KEY not set)")
	case r.SASTError != "":
		medium.Printf("      ⚠  Analysis error: %s\n", r.SASTError)
	case len(r.SASTFindings) == 0:
		green.Println("      ✓  No issues detected")
	default:
		for _, f := range r.SASTFindings {
			p := severityPrinter(f.Severity)
			p.Printf("      [%s]  %s\n", f.Severity, f.Category)
			if f.File != "" {
				fmt.Printf("             File: %s", fileColor.Sprint(f.File))
				if f.Line > 0 {
					fmt.Printf(" line %d", f.Line)
				}
				fmt.Println()
			}
			fmt.Printf("             %s\n", f.Message)
			if f.Snippet != "" {
				dimmed.Printf("             > %s\n", truncate(f.Snippet, 100))
			}
		}
	}
	fmt.Println()

	// ── Summary ───────────────────────────────────────────────────────────
	total := len(r.OSVFindings) + len(r.SecretFindings) + len(r.SASTFindings)
	critical_n := countSeverity(r, "CRITICAL")
	high_n := countSeverity(r, "HIGH")
	medium_n := countSeverity(r, "MEDIUM") + countSeverity(r, "MODERATE")

	bold.Println("  ─────────────────────────────────────────────")
	if total == 0 {
		green.Println("  ✅  All checks passed — safe to commit")
	} else {
		fmt.Printf("  Total findings: %d", total)
		if critical_n > 0 {
			fmt.Printf("  |  ")
			critical.Printf("%d CRITICAL", critical_n)
		}
		if high_n > 0 {
			fmt.Printf("  |  ")
			high.Printf("%d HIGH", high_n)
		}
		if medium_n > 0 {
			fmt.Printf("  |  ")
			medium.Printf("%d MEDIUM", medium_n)
		}
		fmt.Println()

		if critical_n > 0 || len(r.SecretFindings) > 0 {
			fmt.Println()
			critical.Println("  ❌  COMMIT BLOCKED — fix CRITICAL issues and secrets before committing")
		} else if high_n > 0 {
			fmt.Println()
			high.Println("  ⚠️   HIGH severity issues found — review before committing")
		} else {
			fmt.Println()
			medium.Println("  ⚠️   Review findings above before committing")
		}
	}
	fmt.Println()

	_ = severityOrder // used by callers for sorting
}

// ExitCode returns 1 if there are blocking findings (CRITICAL or secrets), 0 otherwise.
func ExitCode(r Results) int {
	if len(r.SecretFindings) > 0 {
		return 1
	}
	for _, f := range r.OSVFindings {
		if strings.ToUpper(f.Severity) == "CRITICAL" {
			return 1
		}
	}
	for _, f := range r.SASTFindings {
		if strings.ToUpper(f.Severity) == "CRITICAL" {
			return 1
		}
	}
	return 0
}

func countSeverity(r Results, sev string) int {
	n := 0
	for _, f := range r.OSVFindings {
		if strings.EqualFold(f.Severity, sev) {
			n++
		}
	}
	for _, f := range r.SASTFindings {
		if strings.EqualFold(f.Severity, sev) {
			n++
		}
	}
	return n
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
