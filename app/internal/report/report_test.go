package report

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/bobbydeveaux/guardian/app/internal/osv"
	"github.com/bobbydeveaux/guardian/app/internal/sast"
	"github.com/bobbydeveaux/guardian/app/internal/secrets"
)

// renderPrint calls Print(r) and returns the captured output. Print mixes
// colour printers (which write via color.Output) and plain fmt.Printf (which
// writes via os.Stdout), so both are redirected and merged.
func renderPrint(t *testing.T, r Results) string {
	t.Helper()
	colorBuf := &bytes.Buffer{}

	prevColor := color.Output
	prevNoColor := color.NoColor
	color.Output = colorBuf
	color.NoColor = true
	defer func() {
		color.Output = prevColor
		color.NoColor = prevNoColor
	}()

	prevStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = pw

	stdoutBuf := &bytes.Buffer{}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(stdoutBuf, pr)
		close(done)
	}()

	Print(r)

	_ = pw.Close()
	<-done
	os.Stdout = prevStdout
	_ = pr.Close()

	// Merge: color.Output and os.Stdout interleave at line boundaries, so a
	// substring search across the union is sufficient for our assertions.
	return colorBuf.String() + "\n" + stdoutBuf.String()
}

func TestSeverityPrinter(t *testing.T) {
	cases := []struct {
		sev  string
		want *color.Color
	}{
		{"CRITICAL", critical},
		{"critical", critical},
		{"HIGH", high},
		{"MEDIUM", medium},
		{"MODERATE", medium},
		{"LOW", low},
		{"UNKNOWN", info},
		{"", info},
	}
	for _, c := range cases {
		if got := severityPrinter(c.sev); got != c.want {
			t.Errorf("severityPrinter(%q) wrong colour", c.sev)
		}
	}
}

func TestSeverityOrder(t *testing.T) {
	cases := []struct {
		sev  string
		want int
	}{
		{"CRITICAL", 0},
		{"HIGH", 1},
		{"MEDIUM", 2},
		{"MODERATE", 2},
		{"LOW", 3},
		{"UNKNOWN", 4},
		{"", 4},
	}
	for _, c := range cases {
		if got := severityOrder(c.sev); got != c.want {
			t.Errorf("severityOrder(%q) = %d, want %d", c.sev, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 100, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is longer", 4, "this…"},
		{"", 5, ""},
	}
	for _, c := range cases {
		if got := truncate(c.in, c.max); got != c.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}

func TestCountSeverity(t *testing.T) {
	r := Results{
		OSVFindings: []osv.Finding{
			{Severity: "CRITICAL"},
			{Severity: "HIGH"},
			{Severity: "high"}, // case-insensitive
		},
		SASTFindings: []sast.Finding{
			{Severity: "CRITICAL"},
			{Severity: "MEDIUM"},
		},
	}
	if got := countSeverity(r, "CRITICAL"); got != 2 {
		t.Errorf("CRITICAL = %d, want 2", got)
	}
	if got := countSeverity(r, "HIGH"); got != 2 {
		t.Errorf("HIGH = %d, want 2", got)
	}
	if got := countSeverity(r, "MEDIUM"); got != 1 {
		t.Errorf("MEDIUM = %d, want 1", got)
	}
	if got := countSeverity(r, "NONE"); got != 0 {
		t.Errorf("NONE = %d, want 0", got)
	}
}

func TestExitCodeClean(t *testing.T) {
	if got := ExitCode(Results{}); got != 0 {
		t.Errorf("clean = %d, want 0", got)
	}
}

func TestExitCodeSecretsBlock(t *testing.T) {
	r := Results{SecretFindings: []secrets.Finding{{Rule: "aws"}}}
	if got := ExitCode(r); got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

func TestExitCodeOSVCriticalBlocks(t *testing.T) {
	r := Results{OSVFindings: []osv.Finding{{Severity: "CRITICAL"}}}
	if got := ExitCode(r); got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

func TestExitCodeSASTCriticalBlocks(t *testing.T) {
	r := Results{SASTFindings: []sast.Finding{{Severity: "CRITICAL"}}}
	if got := ExitCode(r); got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

func TestExitCodeHighOnly(t *testing.T) {
	// HIGH alone does not block (per current rules).
	r := Results{OSVFindings: []osv.Finding{{Severity: "HIGH"}}}
	if got := ExitCode(r); got != 0 {
		t.Errorf("HIGH-only got %d, want 0", got)
	}
}

func TestPrintCleanReport(t *testing.T) {
	out := renderPrint(t, Results{StagedFiles: []string{"main.go"}})
	for _, want := range []string{
		"Guardian",
		"Scanned 1 staged file",
		"No known CVEs found",
		"No secrets detected",
		"All checks passed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestPrintFullScan(t *testing.T) {
	out := renderPrint(t, Results{StagedFiles: []string{"a.go", "b.go"}, FullScan: true})
	if !strings.Contains(out, "Scanned 2 file(s) [full codebase]") {
		t.Errorf("full-scan label missing: %q", out)
	}
}

func TestPrintWithFindings(t *testing.T) {
	out := renderPrint(t, Results{
		StagedFiles: []string{"main.go"},
		OSVFindings: []osv.Finding{
			{Package: "lodash", Version: "4.17.20", ID: "GHSA-x", Summary: "PP", Severity: "CRITICAL"},
		},
		SecretFindings: []secrets.Finding{
			{Rule: "aws_key", File: "main.go", Line: 12, Match: "AKIA…"},
		},
		SASTFindings: []sast.Finding{
			{Category: "SQLi", Message: "string concatenation in query", File: "db.go", Line: 5, Severity: "HIGH", Snippet: "SELECT * FROM users WHERE name='" + strings.Repeat("x", 200) + "'"},
		},
	})
	for _, want := range []string{
		"lodash",
		"GHSA-x",
		"aws_key",
		"SQLi",
		"db.go",
		"COMMIT BLOCKED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nGot:\n%s", want, out)
		}
	}
	// Snippet should be truncated to 100 chars + ellipsis.
	if !strings.Contains(out, "…") {
		t.Errorf("expected truncated snippet ellipsis in output: %s", out)
	}
}

func TestPrintHighOnlyWarns(t *testing.T) {
	out := renderPrint(t, Results{
		StagedFiles:  []string{"x"},
		OSVFindings:  []osv.Finding{{ID: "x", Summary: "x", Severity: "HIGH", Package: "p", Version: "v"}},
		SASTFindings: nil,
	})
	if !strings.Contains(out, "HIGH severity issues") {
		t.Errorf("expected HIGH warning, got: %s", out)
	}
	if strings.Contains(out, "COMMIT BLOCKED") {
		t.Errorf("must not block on HIGH-only: %s", out)
	}
}

func TestPrintMediumOnlyReviews(t *testing.T) {
	out := renderPrint(t, Results{
		StagedFiles:  []string{"x"},
		SASTFindings: []sast.Finding{{Category: "x", Message: "m", Severity: "MEDIUM"}},
	})
	if !strings.Contains(out, "Review findings above") {
		t.Errorf("expected MEDIUM review prompt, got: %s", out)
	}
}

func TestPrintSASTSkipped(t *testing.T) {
	out := renderPrint(t, Results{StagedFiles: []string{"x"}, SASTSkipped: true})
	if !strings.Contains(out, "Skipped") {
		t.Errorf("expected SAST Skipped message")
	}
}

func TestPrintSASTError(t *testing.T) {
	out := renderPrint(t, Results{StagedFiles: []string{"x"}, SASTError: "rate limited"})
	if !strings.Contains(out, "rate limited") {
		t.Errorf("expected SAST error surfaced")
	}
}

func TestPrintSASTWithFileNoLine(t *testing.T) {
	out := renderPrint(t, Results{
		StagedFiles: []string{"x"},
		SASTFindings: []sast.Finding{
			{Category: "Cat", Message: "msg", Severity: "LOW", File: "x.go"}, // Line = 0
		},
	})
	if !strings.Contains(out, "x.go") {
		t.Errorf("file x.go missing from output: %s", out)
	}
	if strings.Contains(out, "line 0") {
		t.Errorf("must not print 'line 0' for Line=0: %s", out)
	}
}
