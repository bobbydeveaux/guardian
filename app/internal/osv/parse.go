// parse.go extracts package lists from common manifest files.
package osv

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

// ParseManifest detects manifest type from filename and returns packages.
func ParseManifest(filename, content string) []Package {
	base := filename
	if idx := strings.LastIndex(filename, "/"); idx >= 0 {
		base = filename[idx+1:]
	}
	switch base {
	case "package.json":
		return parsePackageJSON(content)
	case "requirements.txt":
		return parseRequirements(content)
	case "go.mod":
		return parseGoMod(content)
	case "Gemfile.lock":
		return parseGemfileLock(content)
	case "Pipfile.lock":
		return parsePipfileLock(content)
	}
	return nil
}

// parsePackageJSON parses npm dependencies.
func parsePackageJSON(content string) []Package {
	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(content), &manifest); err != nil {
		return nil
	}
	var pkgs []Package
	for name, ver := range manifest.Dependencies {
		pkgs = append(pkgs, Package{Ecosystem: "npm", Name: name, Version: cleanSemver(ver)})
	}
	for name, ver := range manifest.DevDependencies {
		pkgs = append(pkgs, Package{Ecosystem: "npm", Name: name, Version: cleanSemver(ver)})
	}
	return pkgs
}

// parseRequirements parses Python requirements.txt.
var reqRe = regexp.MustCompile(`^([A-Za-z0-9_.-]+)\s*[=~!><]+\s*([^\s;#]+)`)

func parseRequirements(content string) []Package {
	var pkgs []Package
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := reqRe.FindStringSubmatch(line)
		if m != nil {
			pkgs = append(pkgs, Package{Ecosystem: "PyPI", Name: m[1], Version: m[2]})
		}
	}
	return pkgs
}

// parseGoMod parses go.mod require directives.
var goReqRe = regexp.MustCompile(`^\s+([^\s]+)\s+v([^\s]+)`)

func parseGoMod(content string) []Package {
	var pkgs []Package
	inRequire := false
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "require (") {
			inRequire = true
			continue
		}
		if inRequire && strings.TrimSpace(line) == ")" {
			inRequire = false
			continue
		}
		if inRequire {
			m := goReqRe.FindStringSubmatch(line)
			if m != nil {
				pkgs = append(pkgs, Package{Ecosystem: "Go", Name: m[1], Version: m[2]})
			}
		}
		// single-line: require foo v1.2.3
		if strings.HasPrefix(strings.TrimSpace(line), "require ") {
			parts := strings.Fields(line)
			if len(parts) == 3 {
				ver := strings.TrimPrefix(parts[2], "v")
				pkgs = append(pkgs, Package{Ecosystem: "Go", Name: parts[1], Version: ver})
			}
		}
	}
	return pkgs
}

// parseGemfileLock parses Ruby Gemfile.lock.
var gemRe = regexp.MustCompile(`^\s{4}([a-z][a-z0-9_-]+)\s+\(([^)]+)\)`)

func parseGemfileLock(content string) []Package {
	var pkgs []Package
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		m := gemRe.FindStringSubmatch(sc.Text())
		if m != nil {
			pkgs = append(pkgs, Package{Ecosystem: "RubyGems", Name: m[1], Version: m[2]})
		}
	}
	return pkgs
}

// parsePipfileLock parses Pipfile.lock JSON.
func parsePipfileLock(content string) []Package {
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal([]byte(content), &lock); err != nil {
		return nil
	}
	var pkgs []Package
	for name, info := range lock.Default {
		pkgs = append(pkgs, Package{Ecosystem: "PyPI", Name: name, Version: cleanSemver(info.Version)})
	}
	for name, info := range lock.Develop {
		pkgs = append(pkgs, Package{Ecosystem: "PyPI", Name: name, Version: cleanSemver(info.Version)})
	}
	return pkgs
}

// cleanSemver strips npm-style range prefixes (^, ~, >=, etc.)
func cleanSemver(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "^~>=<")
	v = strings.TrimPrefix(v, "==")
	return v
}

// ParseManifestFile reads a file from disk and parses it.
func ParseManifestFile(path string) []Package {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return ParseManifest(path, string(data))
}
