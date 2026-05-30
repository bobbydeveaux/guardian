package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// initRepo creates a fresh git repo in a temp dir, chdirs into it for the
// duration of the test, and returns the absolute path of the repo.
func initRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	// On macOS t.TempDir() typically lives under /var/folders/... which is a
	// symlink to /private/var/folders/... Resolve it so that path comparisons
	// against `git rev-parse --show-toplevel` match.
	resolved, err := filepath.EvalSymlinks(dir)
	if err == nil {
		dir = resolved
	}

	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(prevWD)
	})

	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		// Force a deterministic identity so commits succeed regardless of
		// the host's global git config.
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@example.com",
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

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func TestStagedFiles(t *testing.T) {
	dir := initRepo(t)
	writeFile(t, dir, "a.txt", "alpha\n")
	writeFile(t, dir, "sub/b.txt", "beta\n")
	gitRun(t, dir, "add", "a.txt", "sub/b.txt")

	files, err := StagedFiles()
	if err != nil {
		t.Fatalf("StagedFiles: %v", err)
	}
	got := strings.Join(files, ",")
	if !strings.Contains(got, "a.txt") || !strings.Contains(got, "sub/b.txt") {
		t.Fatalf("expected staged files a.txt and sub/b.txt, got %q", got)
	}
}

func TestStagedFilesEmpty(t *testing.T) {
	initRepo(t)
	files, err := StagedFiles()
	if err != nil {
		t.Fatalf("StagedFiles: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected no staged files, got %v", files)
	}
}

func TestStagedDiff(t *testing.T) {
	dir := initRepo(t)
	writeFile(t, dir, "a.txt", "alpha\n")
	gitRun(t, dir, "add", "a.txt")

	diff, err := StagedDiff()
	if err != nil {
		t.Fatalf("StagedDiff: %v", err)
	}
	if !strings.Contains(diff, "alpha") {
		t.Fatalf("expected diff to contain new line content, got %q", diff)
	}
	if !strings.Contains(diff, "a.txt") {
		t.Fatalf("expected diff to mention filename, got %q", diff)
	}
}

func TestStagedFileContent(t *testing.T) {
	dir := initRepo(t)
	writeFile(t, dir, "a.txt", "alpha contents\n")
	gitRun(t, dir, "add", "a.txt")

	got, err := StagedFileContent("a.txt")
	if err != nil {
		t.Fatalf("StagedFileContent: %v", err)
	}
	if got != "alpha contents\n" {
		t.Fatalf("expected 'alpha contents\\n', got %q", got)
	}
}

func TestStagedFileContentMissing(t *testing.T) {
	initRepo(t)
	if _, err := StagedFileContent("does-not-exist.txt"); err == nil {
		t.Fatal("expected error for missing staged file")
	}
}

func TestRepoRoot(t *testing.T) {
	dir := initRepo(t)
	got, err := RepoRoot()
	if err != nil {
		t.Fatalf("RepoRoot: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(got)
	if err == nil {
		got = resolved
	}
	if got != dir {
		t.Fatalf("expected repo root %q, got %q", dir, got)
	}
}

func TestRepoRootOutsideRepo(t *testing.T) {
	// Create a non-git dir and chdir into it.
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err == nil {
		dir = resolved
	}
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	if _, err := RepoRoot(); err == nil {
		t.Fatal("expected error when not in a git repo")
	}
}

func TestAllFiles(t *testing.T) {
	dir := initRepo(t)
	writeFile(t, dir, "a.txt", "x")
	writeFile(t, dir, "b/c.txt", "y")
	gitRun(t, dir, "add", "a.txt", "b/c.txt")
	gitRun(t, dir, "commit", "-m", "init", "--no-gpg-sign")

	files, err := AllFiles()
	if err != nil {
		t.Fatalf("AllFiles: %v", err)
	}
	joined := strings.Join(files, ",")
	if !strings.Contains(joined, "a.txt") || !strings.Contains(joined, "b/c.txt") {
		t.Fatalf("expected both tracked files in output, got %q", joined)
	}
}

func TestFileContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := FileContent(path)
	if err != nil {
		t.Fatalf("FileContent: %v", err)
	}
	if got != "hello" {
		t.Fatalf("expected 'hello', got %q", got)
	}
}

func TestFileContentMissing(t *testing.T) {
	if _, err := FileContent("/nonexistent/path/zzz"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
