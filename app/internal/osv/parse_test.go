package osv

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func sortPkgs(pkgs []Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Ecosystem != pkgs[j].Ecosystem {
			return pkgs[i].Ecosystem < pkgs[j].Ecosystem
		}
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
}

func TestParseManifestDispatches(t *testing.T) {
	cases := []struct {
		name     string
		filename string
		content  string
		wantLen  int
	}{
		{"package.json", "package.json", `{"dependencies":{"lodash":"^4.17.20"},"devDependencies":{"jest":"~27.0.0"}}`, 2},
		{"package.json nested path", "frontend/package.json", `{"dependencies":{"react":"18.0.0"}}`, 1},
		{"requirements.txt", "requirements.txt", "flask==2.0.0\ndjango>=3.2\n", 2},
		{"go.mod", "go.mod", "module x\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n)\n", 1},
		{"Gemfile.lock", "Gemfile.lock", "GEMS\n    rails (6.1.0)\n", 1},
		{"Pipfile.lock", "Pipfile.lock", `{"default":{"flask":{"version":"==2.0.0"}}}`, 1},
		{"unknown", "Cargo.toml", "[dependencies]\nfoo = \"1.0\"\n", 0},
		{"package.json no slash", "package.json", `{}`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseManifest(tc.filename, tc.content)
			if len(got) != tc.wantLen {
				t.Errorf("len = %d, want %d (pkgs=%+v)", len(got), tc.wantLen, got)
			}
		})
	}
}

func TestParsePackageJSON(t *testing.T) {
	pkgs := parsePackageJSON(`{
		"dependencies": {"lodash": "^4.17.20", "express": "~4.17.1"},
		"devDependencies": {"jest": ">=27.0.0"}
	}`)
	if len(pkgs) != 3 {
		t.Fatalf("len = %d, want 3", len(pkgs))
	}
	sortPkgs(pkgs)
	want := []Package{
		{Ecosystem: "npm", Name: "express", Version: "4.17.1"},
		{Ecosystem: "npm", Name: "jest", Version: "27.0.0"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
	}
	for i, w := range want {
		if pkgs[i] != w {
			t.Errorf("pkgs[%d] = %+v, want %+v", i, pkgs[i], w)
		}
	}
}

func TestParsePackageJSONMalformed(t *testing.T) {
	if got := parsePackageJSON(`{not valid`); got != nil {
		t.Errorf("got %+v, want nil on malformed JSON", got)
	}
}

func TestParseRequirements(t *testing.T) {
	content := `# A comment
flask==2.0.0
django>=3.2.0
requests~=2.28.0
numpy!=1.20.0
# trailing comment
typing-extensions>=4.0; python_version < "3.10"
`
	pkgs := parseRequirements(content)
	if len(pkgs) != 5 {
		t.Fatalf("len = %d, want 5, got %+v", len(pkgs), pkgs)
	}
	// Make sure flask is parsed correctly.
	var foundFlask bool
	for _, p := range pkgs {
		if p.Name == "flask" {
			foundFlask = true
			if p.Version != "2.0.0" || p.Ecosystem != "PyPI" {
				t.Errorf("flask = %+v", p)
			}
		}
	}
	if !foundFlask {
		t.Error("flask not found")
	}
}

func TestParseRequirementsEmpty(t *testing.T) {
	if got := parseRequirements(""); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
	if got := parseRequirements("# only comments\n# nothing else\n"); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestParseGoMod(t *testing.T) {
	content := `module example.com/x

go 1.21

require (
	github.com/foo/bar v1.2.3
	github.com/baz/qux v0.1.0
)

require github.com/single/dep v2.0.0
`
	pkgs := parseGoMod(content)
	if len(pkgs) != 3 {
		t.Fatalf("len = %d, want 3, got %+v", len(pkgs), pkgs)
	}
	sortPkgs(pkgs)
	wantNames := []string{"github.com/baz/qux", "github.com/foo/bar", "github.com/single/dep"}
	for i, n := range wantNames {
		if pkgs[i].Name != n {
			t.Errorf("pkgs[%d].Name = %q, want %q", i, pkgs[i].Name, n)
		}
		if pkgs[i].Ecosystem != "Go" {
			t.Errorf("pkgs[%d].Ecosystem = %q, want Go", i, pkgs[i].Ecosystem)
		}
	}
}

func TestParseGoModEmpty(t *testing.T) {
	if got := parseGoMod(""); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
	if got := parseGoMod("module x\n\ngo 1.21\n"); got != nil {
		t.Errorf("got %+v, want nil when no requires", got)
	}
}

func TestParseGemfileLock(t *testing.T) {
	content := `GEM
  remote: https://rubygems.org/
  specs:
    rails (6.1.0)
    rack (2.2.3)
    actionview (6.1.0)
`
	pkgs := parseGemfileLock(content)
	if len(pkgs) != 3 {
		t.Fatalf("len = %d, want 3, got %+v", len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		if p.Ecosystem != "RubyGems" {
			t.Errorf("%+v ecosystem != RubyGems", p)
		}
	}
}

func TestParseGemfileLockEmpty(t *testing.T) {
	if got := parseGemfileLock(""); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestParsePipfileLock(t *testing.T) {
	content := `{
		"default": {"flask": {"version": "==2.0.0"}, "requests": {"version": "==2.28.0"}},
		"develop": {"pytest": {"version": "==7.0.0"}}
	}`
	pkgs := parsePipfileLock(content)
	if len(pkgs) != 3 {
		t.Fatalf("len = %d, want 3, got %+v", len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		if p.Ecosystem != "PyPI" {
			t.Errorf("%+v ecosystem != PyPI", p)
		}
		// Versions should have == stripped by cleanSemver.
		if p.Version == "==2.0.0" {
			t.Errorf("version not cleaned: %+v", p)
		}
	}
}

func TestParsePipfileLockMalformed(t *testing.T) {
	if got := parsePipfileLock(`{bad json`); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestCleanSemver(t *testing.T) {
	cases := []struct{ in, want string }{
		{"^1.2.3", "1.2.3"},
		{"~1.2.3", "1.2.3"},
		{">=1.0.0", "1.0.0"},
		{"==2.0.0", "2.0.0"},
		{"<1.0.0", "1.0.0"},
		{"  1.0.0  ", "1.0.0"},
		{"1.0.0", "1.0.0"},
		{"", ""},
	}
	for _, c := range cases {
		if got := cleanSemver(c.in); got != c.want {
			t.Errorf("cleanSemver(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseManifestFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(`{"dependencies":{"react":"18.0.0"}}`), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	pkgs := ParseManifestFile(path)
	if len(pkgs) != 1 || pkgs[0].Name != "react" {
		t.Errorf("pkgs = %+v, want [react]", pkgs)
	}
}

func TestParseManifestFileMissing(t *testing.T) {
	if got := ParseManifestFile(filepath.Join(t.TempDir(), "no-such-file")); got != nil {
		t.Errorf("got %+v, want nil for missing file", got)
	}
}
