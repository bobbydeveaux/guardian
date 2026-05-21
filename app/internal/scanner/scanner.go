// Package scanner orchestrates all security checks.
package scanner

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/bobbydeveaux/guardian/app/internal/git"
	"github.com/bobbydeveaux/guardian/app/internal/osv"
	"github.com/bobbydeveaux/guardian/app/internal/report"
	"github.com/bobbydeveaux/guardian/app/internal/sast"
	"github.com/bobbydeveaux/guardian/app/internal/secrets"
)

// Options controls which checks are enabled.
type Options struct {
	OSV     bool
	Secrets bool
	SAST    bool
	Full    bool // scan entire repo instead of just staged files
}

// DefaultOptions enables all checks.
var DefaultOptions = Options{OSV: true, Secrets: true, SAST: true}

// binaryExtensions are skipped for secrets and SAST scanning.
var binaryExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
	".svg": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".pdf": true, ".zip": true, ".tar": true, ".gz": true, ".exe": true,
	".dll": true, ".so": true, ".dylib": true, ".bin": true, ".lock": true,
	".sum": true, ".map": true, ".min.js": true,
}

// ignoredDirs are skipped entirely in full mode.
var ignoredDirs = []string{
	"node_modules/", "vendor/", ".git/", "dist/", "build/", "__pycache__/",
	".venv/", "venv/", ".next/", ".nuxt/", "coverage/",
}

// sourceExtensions are scanned for SAST in full mode (limit noise).
var sourceExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".java": true, ".rb": true, ".php": true, ".cs": true, ".cpp": true, ".c": true,
	".sh": true, ".bash": true, ".env": true, ".yaml": true, ".yml": true,
	".toml": true, ".tf": true, ".rs": true, ".kt": true, ".swift": true,
}

// loadIgnoreFile reads a .guardianignore file from the given root directory.
// It returns a slice of patterns (one per line). Blank lines and lines starting
// with '#' are skipped. If the file does not exist, it returns nil with no error.
func loadIgnoreFile(root string) []string {
	f, err := os.Open(filepath.Join(root, ".guardianignore"))
	if err != nil {
		return nil
	}
	defer f.Close()

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns
}

// matchesIgnorePattern checks whether a relative path matches any of the user-
// supplied ignore patterns. Directory patterns (ending with '/') match via
// prefix; other patterns are matched as file globs against the base name.
func matchesIgnorePattern(relPath string, patterns []string) bool {
	for _, p := range patterns {
		if strings.HasSuffix(p, "/") {
			// Directory pattern — match if path starts with the dir or contains it as a component.
			dir := p // e.g. "web/"
			if strings.HasPrefix(relPath, dir) || strings.Contains(relPath, "/"+dir) {
				return true
			}
		} else {
			// Glob pattern — match against the file's base name.
			base := filepath.Base(relPath)
			if matched, _ := filepath.Match(p, base); matched {
				return true
			}
		}
	}
	return false
}

func isIgnoredPath(path string, userPatterns []string) bool {
	for _, dir := range ignoredDirs {
		if strings.HasPrefix(path, dir) || strings.Contains(path, "/"+dir) {
			return true
		}
	}
	if matchesIgnorePattern(path, userPatterns) {
		return true
	}
	return false
}

// walkAllFiles walks the directory tree from root, returning all non-ignored, non-binary file paths.
func walkAllFiles(root string, userPatterns []string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		// Make path relative to root for consistent filtering
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if isIgnoredPath(rel+"/", userPatterns) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isIgnoredPath(rel, userPatterns) {
			files = append(files, rel)
		}
		return nil
	})
	return files, err
}

func isBinary(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return binaryExtensions[ext]
}

func isSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return sourceExtensions[ext]
}

// Run executes all enabled scans and returns a Results object.
func Run(opts Options) (report.Results, error) {
	var results report.Results
	results.FullScan = opts.Full

	files, err := resolveScanFiles(opts)
	if err != nil {
		return results, err
	}
	results.StagedFiles = files

	if len(files) == 0 {
		return results, nil
	}

	fileContents := loadFileContents(opts, files)

	if opts.OSV {
		runOSV(fileContents, &results)
	}

	if opts.Secrets {
		results.SecretFindings = secrets.ScanFiles(fileContents)
	}

	if opts.SAST {
		runSAST(opts, fileContents, &results)
	}

	return results, nil
}

// resolveScanFiles determines which files to scan based on the mode (full or
// staged) and the .guardianignore patterns at the repo root.
func resolveScanFiles(opts Options) ([]string, error) {
	root, rootErr := git.RepoRoot()
	if rootErr != nil {
		root, _ = os.Getwd()
	}
	userPatterns := loadIgnoreFile(root)

	if opts.Full {
		relFiles, walkErr := walkAllFiles(root, userPatterns)
		if walkErr != nil {
			return nil, fmt.Errorf("could not walk repo: %w", walkErr)
		}
		// Store absolute paths so os.ReadFile works regardless of CWD.
		files := make([]string, len(relFiles))
		for i, f := range relFiles {
			files[i] = filepath.Join(root, f)
		}
		return files, nil
	}

	staged, stagedErr := git.StagedFiles()
	if stagedErr != nil {
		return nil, fmt.Errorf("could not list staged files: %w", stagedErr)
	}
	files := make([]string, 0, len(staged))
	for _, f := range staged {
		if !matchesIgnorePattern(f, userPatterns) {
			files = append(files, f)
		}
	}
	return files, nil
}

// loadFileContents reads the contents of every non-binary file using either
// the full-tree or staged-blob git accessor. Unreadable files are silently
// skipped, matching the original Run behaviour.
func loadFileContents(opts Options, files []string) map[string]string {
	fileContents := make(map[string]string, len(files))
	for _, f := range files {
		if isBinary(f) {
			continue
		}
		var content string
		var readErr error
		if opts.Full {
			content, readErr = git.FileContent(f)
		} else {
			content, readErr = git.StagedFileContent(f)
		}
		if readErr == nil {
			fileContents[f] = content
		}
	}
	return fileContents
}

// runOSV parses every file as a manifest and queries the OSV database for
// each discovered package. Errors are swallowed to match original behaviour.
func runOSV(fileContents map[string]string, results *report.Results) {
	var packages []osv.Package
	for filename, content := range fileContents {
		pkgs := osv.ParseManifest(filename, content)
		packages = append(packages, pkgs...)
	}
	if len(packages) == 0 {
		return
	}
	fmt.Printf("  → Checking %d packages against OSV database...\n", len(packages))
	findings, err := osv.ScanPackages(packages)
	if err == nil {
		results.OSVFindings = findings
	}
}

// runSAST dispatches the SAST step to either the full-mode (file-based) or
// staged-mode (diff-based) Claude analyser.
func runSAST(opts Options, fileContents map[string]string, results *report.Results) {
	if opts.Full {
		runSASTFull(fileContents, results)
		return
	}
	runSASTStaged(results)
}

// runSASTFull filters to source files and asks Claude to analyse them.
func runSASTFull(fileContents map[string]string, results *report.Results) {
	sourceFiles := make(map[string]string)
	for name, content := range fileContents {
		if isSourceFile(name) {
			sourceFiles[name] = content
		}
	}
	if len(sourceFiles) == 0 {
		results.SASTSkipped = true
		return
	}
	fmt.Printf("  → Running Claude AI analysis on %d source file(s)...\n", len(sourceFiles))
	findings, err := sast.AnalyseFiles(sourceFiles)
	if err != nil {
		results.SASTSkipped = true
		results.SASTError = err.Error()
		return
	}
	results.SASTFindings = findings
}

// runSASTStaged asks Claude to analyse the staged diff.
func runSASTStaged(results *report.Results) {
	diff, err := git.StagedDiff()
	if err != nil || strings.TrimSpace(diff) == "" {
		results.SASTSkipped = true
		return
	}
	fmt.Println("  → Running Claude AI code analysis...")
	findings, err := sast.AnalyseDiff(diff)
	if err != nil {
		results.SASTSkipped = true
		results.SASTError = err.Error()
		return
	}
	results.SASTFindings = findings
}
