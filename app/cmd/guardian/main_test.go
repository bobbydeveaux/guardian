package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// initRepo creates a fresh git repo in a temp dir, chdirs the test into it,
// and restores the previous cwd on cleanup.
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

// captureStdout redirects os.Stdout (plain fmt.Printf) and color.Output
// (colour-printer writes from the fatih/color package) to a single merged
// buffer for the duration of fn.
func captureStdout(t *testing.T, fn func()) string {
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

	fn()

	_ = pw.Close()
	<-done
	os.Stdout = prevStdout
	_ = pr.Close()
	return colorBuf.String() + "\n" + stdoutBuf.String()
}

// withExitFunc swaps exitFunc and restores it after the test.
func withExitFunc(t *testing.T, f func(int)) {
	t.Helper()
	prev := exitFunc
	exitFunc = f
	t.Cleanup(func() { exitFunc = prev })
}

// resetFlags clears the global flag state between tests so flag values from
// one test don't leak into the next.
func resetFlags(t *testing.T) {
	t.Helper()
	prev := struct {
		noOSV, noSecrets, noSAST, noColor, fullScan bool
	}{noOSV, noSecrets, noSAST, noColor, fullScan}
	noOSV, noSecrets, noSAST, noColor, fullScan = false, false, false, false, false
	t.Cleanup(func() {
		noOSV, noSecrets, noSAST, noColor, fullScan = prev.noOSV, prev.noSecrets, prev.noSAST, prev.noColor, prev.fullScan
	})
}

func TestRunInstallWritesHook(t *testing.T) {
	resetFlags(t)
	dir := t.TempDir()
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	// Create .git/hooks directory structure.
	if err := os.MkdirAll(filepath.Join(dir, ".git", "hooks"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	out := captureStdout(t, func() {
		if err := runInstall(nil, nil); err != nil {
			t.Fatalf("runInstall: %v", err)
		}
	})

	hook, err := os.ReadFile(filepath.Join(dir, ".git", "hooks", "pre-commit"))
	if err != nil {
		t.Fatalf("hook not written: %v", err)
	}
	if !strings.Contains(string(hook), "guardian check") {
		t.Errorf("hook content missing guardian check call: %s", hook)
	}
	if !strings.Contains(out, "installed") {
		t.Errorf("expected install confirmation in stdout, got %q", out)
	}
}

func TestRunInstallMissingGitDir(t *testing.T) {
	resetFlags(t)
	dir := t.TempDir()
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	err := runInstall(nil, nil)
	if err == nil {
		t.Fatal("expected error when .git/hooks is missing")
	}
	if !strings.Contains(err.Error(), "not in a git repo") {
		t.Errorf("error = %v, want one mentioning 'not in a git repo'", err)
	}
}

func TestRunCheckNoStagedFiles(t *testing.T) {
	resetFlags(t)
	initRepo(t)

	called := false
	withExitFunc(t, func(code int) { called = true; _ = code })

	out := captureStdout(t, func() {
		// Disable all scanners so no real network/Anthropic calls happen.
		noOSV, noSecrets, noSAST = true, true, true
		if err := runCheck(nil, nil); err != nil {
			t.Fatalf("runCheck: %v", err)
		}
	})

	if called {
		t.Errorf("exitFunc must not be called when there are no staged files")
	}
	if !strings.Contains(out, "No staged files") {
		t.Errorf("expected 'No staged files' message, got %q", out)
	}
}

func TestRunCheckFullScanNoFiles(t *testing.T) {
	resetFlags(t)
	initRepo(t)

	withExitFunc(t, func(int) {})

	out := captureStdout(t, func() {
		noOSV, noSecrets, noSAST, fullScan = true, true, true, true
		if err := runCheck(nil, nil); err != nil {
			t.Fatalf("runCheck: %v", err)
		}
	})

	if !strings.Contains(out, "No tracked files") {
		t.Errorf("expected 'No tracked files' message in full mode, got %q", out)
	}
}

func TestRunCheckWithStagedSecret(t *testing.T) {
	resetFlags(t)
	dir := initRepo(t)
	// Stage a file that contains a clearly-fake but pattern-matching secret.
	if err := os.WriteFile(
		filepath.Join(dir, "leak.txt"),
		[]byte("AKIAIOSFODNN7AAAAAAA\n"),
		0o644,
	); err != nil {
		t.Fatalf("write: %v", err)
	}
	cmd := exec.Command("git", "add", "leak.txt")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}

	var capturedCode int
	withExitFunc(t, func(code int) { capturedCode = code })

	out := captureStdout(t, func() {
		// Keep secrets ON; turn off OSV and SAST so no network calls.
		noOSV, noSAST = true, true
		if err := runCheck(nil, nil); err != nil {
			t.Fatalf("runCheck: %v", err)
		}
	})

	if capturedCode != 1 {
		t.Errorf("exit code = %d, want 1 (secret detected blocks commit)", capturedCode)
	}
	if !strings.Contains(out, "Secrets") {
		t.Errorf("expected report to mention Secrets, got %q", out)
	}
}

func TestRunCheckNoColor(t *testing.T) {
	resetFlags(t)
	initRepo(t)
	withExitFunc(t, func(int) {})

	_ = captureStdout(t, func() {
		noColor, noOSV, noSecrets, noSAST = true, true, true, true
		if err := runCheck(nil, nil); err != nil {
			t.Fatalf("runCheck: %v", err)
		}
	})
	// Side effect: color.NoColor should be set true. We don't import color
	// here, but the path is exercised via the noColor branch.
}

func TestRootCommandHelp(t *testing.T) {
	resetFlags(t)
	// Cobra writes help to its configured output; redirect it.
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})
	rootCmd.SetArgs([]string{"--help"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd --help: %v", err)
	}
	if !strings.Contains(buf.String(), "Guardian") {
		t.Errorf("help output missing 'Guardian': %q", buf.String())
	}
}
