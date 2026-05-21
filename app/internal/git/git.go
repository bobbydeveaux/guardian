// Package git provides helpers for reading staged changes from the local repo.
package git

import (
	"os"
	"os/exec"
	"strings"
)

// StagedFiles returns the list of files currently staged (git diff --cached --name-only).
func StagedFiles() ([]string, error) {
	out, err := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACMR").Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

// StagedDiff returns the full unified diff of all staged changes.
func StagedDiff() (string, error) {
	out, err := exec.Command("git", "diff", "--cached", "-U3").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// StagedFileContent returns the staged content of a specific file.
func StagedFileContent(path string) (string, error) {
	out, err := exec.Command("git", "show", ":"+path).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// RepoRoot returns the root directory of the current git repository.
func RepoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// AllFiles returns every file tracked by git in the current repository.
func AllFiles() ([]string, error) {
	out, err := exec.Command("git", "ls-files").Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

// FileContent reads a file directly from disk (used for full-codebase scans).
func FileContent(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
