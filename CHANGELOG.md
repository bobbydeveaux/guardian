# Changelog

All notable changes to Guardian are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Guardian adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **GitHub Marketplace billing webhook** (agentops-014, 6b00a1d) — `POST /webhook/github-marketplace` reads the raw request body (1 MiB cap), verifies `X-Hub-Signature-256` against `GITHUB_WEBHOOK_SECRET` via constant-time HMAC-SHA256, and logs one structured line per accepted `marketplace_purchase` action. The five recognised actions are `purchased`, `cancelled`, `changed`, `pending_change`, and `pending_change_cancelled`; any other action returns `422` so misconfigurations surface loudly. Missing `GITHUB_WEBHOOK_SECRET` fails loud with `500`. Ships as a stdlib-only Cloud Run image via `Dockerfile.webhook`, exposing `GET /health` for liveness probes (PR #3).
- **`internal/git`, `internal/scanner`, `internal/sast`, `internal/secrets` test suites** — coverage raised from 0%/0%/0%/59% to 91%/65%/92%/100% via t.TempDir() git repos, httptest mocks of the Anthropic API, and table-driven rule tests (agentops-052, da488e6, PR #5).
- **`internal/osv`, `internal/report`, `cmd/guardian` test suites** — coverage raised from 0%/0%/0% to 99%/100%/69% via httptest mocks of the OSV API, table-driven manifest-parser tests, and an injectable `exitFunc` seam for `runCheck` (agentops-053, 5d85fae, PR #6). App-wide statement coverage now sits at 85.5%.
- **`internal/scanner` orchestration test coverage** — `runOSV`, `runSAST`, `runSASTFull`, and `runSASTStaged` raised from 0% to ≥60% via 10 new tests in `scanner_test.go` that exercise the happy path, the empty-input skip path, and the upstream-API error path for each function. Added `SetAPIForTest(t *testing.T, url string)` test-only seams to `internal/osv` and `internal/sast` so `httptest` servers can stand in for the OSV and Anthropic endpoints across package boundaries; staged-mode scenarios reuse the existing `initRepo(t)` helper. No production behaviour changed (agentops-055, f204e0a, PR #8).

### Changed
- **`internal/scanner` extracted SAST + file-loading helpers** — scanner refactored so the SAST batch path and the file-loading path are isolated helpers, simplifying the scan orchestration in `Run` and unblocking the package-level coverage uplift (d363183, PR #4).

## [0.1.0] - 2026-05-18

### Added
- Initial public release of Guardian — local pre-commit security scanner combining OSV dependency CVE checks, 15+ secrets-detection regex rules, and Claude Haiku SAST against the staged diff (712b997).
- `guardian install` adds a pre-commit hook to the current repo; `guardian check` runs all enabled scanners against the git staging area; `--no-sast` / `--no-osv` / `--no-secrets` / `--no-color` flags selectively disable scanners or simplify output for CI.
- GitHub Action wrapper (`action.yml`) at `bobbydeveaux/guardian@main` runs Guardian against a repo checkout with configurable `anthropic_api_key`, `scan_osv`, `scan_secrets`, `scan_sast`, and `fail_on_findings` inputs.
- Manifest parsers cover `package.json`, `requirements.txt`, `go.mod`, `Gemfile.lock`, and `Pipfile.lock` against the Google OSV API.
- Exit code contract — `0` when clear (or only LOW/MEDIUM findings) and `1` on any CRITICAL issue or secret detection.
