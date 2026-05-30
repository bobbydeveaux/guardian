package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsBinary(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"foo.png", true},
		{"foo.PNG", true},
		{"foo.jpg", true},
		{"foo.go", false},
		{"path/to/file.pdf", true},
		{"README", false},
		{"foo.sum", true},
		{"foo.lock", true},
	}
	for _, c := range cases {
		if got := isBinary(c.path); got != c.want {
			t.Errorf("isBinary(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestIsSourceFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"main.go", true},
		{"app.py", true},
		{"index.ts", true},
		{"image.png", false},
		{"README.md", false},
		{"deploy.yaml", true},
		{"deploy.yml", true},
		{"Cargo.toml", true},
		{"infra.tf", true},
		{"App.swift", true},
	}
	for _, c := range cases {
		if got := isSourceFile(c.path); got != c.want {
			t.Errorf("isSourceFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestMatchesIgnorePattern(t *testing.T) {
	patterns := []string{"build/", "*.log", "secrets.env"}
	cases := []struct {
		path string
		want bool
	}{
		{"build/output.txt", true},          // dir prefix
		{"src/build/output.txt", true},      // dir as component
		{"src/main.go", false},              // unrelated
		{"app.log", true},                   // glob match on base name
		{"logs/app.log", true},              // glob still matches base
		{"secrets.env", true},               // exact base match
		{"infra/secrets.env", true},         // base name match
		{"infra/secrets.env.example", false}, // base doesn't match
	}
	for _, c := range cases {
		if got := matchesIgnorePattern(c.path, patterns); got != c.want {
			t.Errorf("matchesIgnorePattern(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestIsIgnoredPath(t *testing.T) {
	user := []string{"build/", "*.log"}
	cases := []struct {
		path string
		want bool
	}{
		{"node_modules/foo.js", true},
		{"src/.git/index", true},
		{"build/output.txt", true},
		{"app.log", true},
		{"src/main.go", false},
	}
	for _, c := range cases {
		if got := isIgnoredPath(c.path, user); got != c.want {
			t.Errorf("isIgnoredPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestLoadIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	content := "# comment line\n\nbuild/\n*.log\n"
	if err := os.WriteFile(filepath.Join(dir, ".guardianignore"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	patterns := loadIgnoreFile(dir)
	if len(patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d (%v)", len(patterns), patterns)
	}
	if patterns[0] != "build/" || patterns[1] != "*.log" {
		t.Errorf("unexpected patterns: %v", patterns)
	}
}

func TestLoadIgnoreFileMissing(t *testing.T) {
	dir := t.TempDir()
	if got := loadIgnoreFile(dir); got != nil {
		t.Errorf("expected nil for missing ignore file, got %v", got)
	}
}

func TestWalkAllFiles(t *testing.T) {
	dir := t.TempDir()
	// Build a small tree.
	mkDir := func(p string) { _ = os.MkdirAll(filepath.Join(dir, p), 0o755) }
	mk := func(p, c string) {
		full := filepath.Join(dir, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(c), 0o644)
	}
	mk("a.go", "x")
	mk("b/c.go", "y")
	mkDir("node_modules")
	mk("node_modules/bad.js", "z")
	mk("d.log", "should-ignore-via-user-pattern")

	files, err := walkAllFiles(dir, []string{"*.log"})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	joined := strings.Join(files, "|")
	if !strings.Contains(joined, "a.go") || !strings.Contains(joined, "b/c.go") {
		t.Errorf("expected a.go and b/c.go, got %q", joined)
	}
	if strings.Contains(joined, "node_modules") {
		t.Errorf("expected node_modules to be skipped, got %q", joined)
	}
	if strings.Contains(joined, "d.log") {
		t.Errorf("expected user pattern to ignore d.log, got %q", joined)
	}
}

// initRepo returns a fresh git repo dir; the test's CWD is changed to it for the
// duration. This mirrors the helper in the git package tests so we can exercise
// resolveScanFiles in both modes.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "-q")
	run("config", "commit.gpgsign", "false")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	return dir
}

func TestResolveScanFilesStaged(t *testing.T) {
	dir := initRepo(t)
	// stage two files: one normal, one ignored by .guardianignore glob
	_ = os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "skip.log"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, ".guardianignore"), []byte("*.log\n"), 0o644)
	cmd := exec.Command("git", "add", "a.go", "skip.log", ".guardianignore")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}

	files, err := resolveScanFiles(Options{})
	if err != nil {
		t.Fatalf("resolveScanFiles: %v", err)
	}
	joined := strings.Join(files, "|")
	if !strings.Contains(joined, "a.go") {
		t.Errorf("expected a.go to be included, got %q", joined)
	}
	if strings.Contains(joined, "skip.log") {
		t.Errorf("expected skip.log to be filtered, got %q", joined)
	}
}

func TestResolveScanFilesFull(t *testing.T) {
	dir := initRepo(t)
	_ = os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a"), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "node_modules/x.js"), []byte("x"), 0o644)

	files, err := resolveScanFiles(Options{Full: true})
	if err != nil {
		t.Fatalf("resolveScanFiles full: %v", err)
	}
	joined := strings.Join(files, "|")
	if !strings.Contains(joined, "a.go") {
		t.Errorf("expected a.go in full scan, got %q", joined)
	}
	if strings.Contains(joined, "node_modules") {
		t.Errorf("expected node_modules to be skipped in full scan, got %q", joined)
	}
}

func TestLoadFileContentsSkipsBinary(t *testing.T) {
	dir := initRepo(t)
	_ = os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "logo.png"), []byte("\x89PNG"), 0o644)

	contents := loadFileContents(
		Options{Full: true},
		[]string{filepath.Join(dir, "a.go"), filepath.Join(dir, "logo.png")},
	)
	// .png is in binaryExtensions so it should not be loaded.
	if _, ok := contents[filepath.Join(dir, "logo.png")]; ok {
		t.Errorf("expected binary file to be skipped")
	}
	if _, ok := contents[filepath.Join(dir, "a.go")]; !ok {
		t.Errorf("expected a.go to be loaded, got %v", contents)
	}
}

func TestRunStagedNoFiles(t *testing.T) {
	// In a clean repo with no staged files, Run should return without error
	// and produce no findings.
	initRepo(t)
	results, err := Run(Options{Secrets: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results.StagedFiles) != 0 {
		t.Errorf("expected no staged files, got %v", results.StagedFiles)
	}
	if len(results.SecretFindings) != 0 {
		t.Errorf("expected no findings, got %v", results.SecretFindings)
	}
}

func TestRunStagedSecretsOnly(t *testing.T) {
	dir := initRepo(t)
	// Stage a file that contains a clearly-fake but pattern-matching secret.
	_ = os.WriteFile(
		filepath.Join(dir, "leak.txt"),
		[]byte("AKIAIOSFODNN7AAAAAAA\n"),
		0o644,
	)
	cmd := exec.Command("git", "add", "leak.txt")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}

	results, err := Run(Options{Secrets: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results.SecretFindings) == 0 {
		t.Fatalf("expected secret findings, got none")
	}
}
