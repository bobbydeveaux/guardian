# Guardian — Local Pre-Commit Security Scanner

> A fast, local security scanner inspired by Checkmarx/Snyk. Runs in milliseconds before every commit.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-blue.svg)](app/go.mod)

## What it checks

| Check | Description |
|-------|-------------|
| 📦 **OSV Dependency CVEs** | Scans `package.json`, `requirements.txt`, `go.mod`, `Gemfile.lock` against the Google OSV database |
| 🔑 **Secrets Detection** | 15+ regex patterns for API keys, passwords, AWS credentials, GitHub tokens, JWTs, connection strings |
| 🧠 **Claude AI SAST** | Sends your staged diff to Claude Haiku for code-level security analysis (SQL injection, XSS, path traversal, etc.) |

## Repository Layout

```
guardian/
├── app/          # Go CLI source
│   ├── cmd/
│   ├── internal/
│   ├── go.mod
│   └── ...
├── website/      # Static marketing site
│   ├── index.html
│   └── launchpad.yaml
└── README.md
```

## Quick Install

```bash
go install github.com/bobbydeveaux/guardian/app/cmd/guardian@latest

export ANTHROPIC_API_KEY=sk-ant-...   # optional — for AI SAST

guardian install   # adds pre-commit hook to current repo
```

## Usage

```bash
# Scan staged changes
guardian check

# Install as pre-commit hook (auto-scans every commit)
guardian install

# Skip individual checks
guardian check --no-sast       # skip Claude analysis
guardian check --no-osv        # skip dependency scan
guardian check --no-secrets    # skip secrets scan
guardian check --no-color      # CI-friendly output
```

## Exit codes

- `0` — all clear (or only LOW/MEDIUM warnings)
- `1` — CRITICAL issue or secret detected (commit blocked)

## Build from source

```bash
cd app
go build -o guardian ./cmd/guardian/
```

## Licence

MIT
