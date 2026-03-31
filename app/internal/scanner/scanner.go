// Package scanner orchestrates all security checks.
package scanner

import (
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

func isIgnoredPath(path string) bool {
	for _, dir := range ignoredDirs {
		if strings.HasPrefix(path, dir) || strings.Contains(path, "/"+dir) {
			return true
		}
	}
	return false
}

// walkAllFiles walks the directory tree from root, returning all non-ignored, non-binary file paths.
func walkAllFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		// Make path relative to root for consistent filtering
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if isIgnoredPath(rel + "/") {
				return filepath.SkipDir
			}
			return nil
		}
		if !isIgnoredPath(rel) {
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

	var files []string
	var err error

	if opts.Full {
		root, rootErr := git.RepoRoot()
		if rootErr != nil {
			root, _ = os.Getwd()
		}
		relFiles, walkErr := walkAllFiles(root)
		if walkErr != nil {
			return results, fmt.Errorf("could not walk repo: %w", walkErr)
		}
		// Store absolute paths so os.ReadFile works regardless of CWD
		files = make([]string, len(relFiles))
		for i, f := range relFiles {
			files[i] = filepath.Join(root, f)
		}
	} else {
		files, err = git.StagedFiles()
		if err != nil {
			return results, fmt.Errorf("could not list staged files: %w", err)
		}
	}

	results.StagedFiles = files

	if len(files) == 0 {
		return results, nil
	}

	// Load file contents
	fileContents := make(map[string]string)
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

	// OSV — scan manifest files
	if opts.OSV {
		var packages []osv.Package
		for filename, content := range fileContents {
			pkgs := osv.ParseManifest(filename, content)
			packages = append(packages, pkgs...)
		}
		if len(packages) > 0 {
			fmt.Printf("  → Checking %d packages against OSV database...\n", len(packages))
			findings, err := osv.ScanPackages(packages)
			if err == nil {
				results.OSVFindings = findings
			}
		}
	}

	// Secrets — scan all non-binary files
	if opts.Secrets {
		results.SecretFindings = secrets.ScanFiles(fileContents)
	}

	// SAST
	if opts.SAST {
		if opts.Full {
			// Filter to source files only to keep batches focused
			sourceFiles := make(map[string]string)
			for name, content := range fileContents {
				if isSourceFile(name) {
					sourceFiles[name] = content
				}
			}
			if len(sourceFiles) == 0 {
				results.SASTSkipped = true
			} else {
				fmt.Printf("  → Running Claude AI analysis on %d source file(s)...\n", len(sourceFiles))
				findings, err := sast.AnalyseFiles(sourceFiles)
				if err != nil {
					results.SASTSkipped = true
					results.SASTError = err.Error()
				} else {
					results.SASTFindings = findings
				}
			}
		} else {
			diff, err := git.StagedDiff()
			if err != nil || strings.TrimSpace(diff) == "" {
				results.SASTSkipped = true
			} else {
				fmt.Println("  → Running Claude AI code analysis...")
				findings, err := sast.AnalyseDiff(diff)
				if err != nil {
					results.SASTSkipped = true
					results.SASTError = err.Error()
				} else {
					results.SASTFindings = findings
				}
			}
		}
	}

	return results, nil
}
