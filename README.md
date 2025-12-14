# kev-checker

Check your dependencies for CISA Known Exploited Vulnerabilities (KEV).

[![Test](https://github.com/ethanolivertroy/kev-checker/actions/workflows/test.yml/badge.svg)](https://github.com/ethanolivertroy/kev-checker/actions/workflows/test.yml)

## Overview

`kev-checker` scans your project dependencies and identifies any that have known exploited vulnerabilities tracked by [CISA's KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). These are vulnerabilities that are actively being exploited in the wild.

The tool:
1. Parses your dependency files (requirements.txt, package.json, go.mod, etc.)
2. Queries the [OSV database](https://osv.dev/) to find CVEs affecting your dependencies
3. Cross-references CVEs against the CISA KEV catalog
4. Enriches results with [EPSS scores](https://www.first.org/epss/) (Exploit Prediction Scoring System)

## Supported Ecosystems

| Ecosystem | Files |
|-----------|-------|
| Python | `requirements.txt`, `pyproject.toml` |
| Node.js | `package.json`, `package-lock.json` |
| Go | `go.mod` |

## Installation

### Binary Release

Download the latest release for your platform from [Releases](https://github.com/ethanolivertroy/kev-checker/releases).

```bash
# Linux (amd64)
curl -sL https://github.com/ethanolivertroy/kev-checker/releases/latest/download/kev-checker-linux-amd64 -o kev-checker
chmod +x kev-checker

# macOS (arm64 / Apple Silicon)
curl -sL https://github.com/ethanolivertroy/kev-checker/releases/latest/download/kev-checker-darwin-arm64 -o kev-checker
chmod +x kev-checker
```

### From Source

```bash
go install github.com/ethanolivertroy/kev-checker@latest
```

## Usage

### CLI

```bash
# Scan current directory
kev-checker

# Scan specific paths
kev-checker ./app ./services

# Output as JSON
kev-checker --format json

# Output SARIF for GitHub Code Scanning
kev-checker --format sarif --output results.sarif

# Don't fail on KEV findings (exit 0 regardless)
kev-checker --no-fail

# Only report if EPSS score >= 10%
kev-checker --epss-threshold 0.1

# Skip cache (always fetch fresh KEV data)
kev-checker --no-cache
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--format`, `-f` | `terminal` | Output format: `terminal`, `json`, `sarif` |
| `--output`, `-o` | stdout | Output file path |
| `--epss-threshold` | `0` | Only report KEVs with EPSS >= threshold (0-1) |
| `--no-fail` | `false` | Don't exit with error code if KEVs found |
| `--no-cache` | `false` | Disable KEV data caching |
| `--timeout` | `60` | HTTP request timeout in seconds |

### Exit Codes

| Code | Description |
|------|-------------|
| 0 | No KEV vulnerabilities found |
| 1 | KEV vulnerabilities found (unless `--no-fail`) |
| 2 | Error occurred |

## GitHub Action

Use kev-checker as a GitHub Action to automatically check dependencies on every PR:

```yaml
name: KEV Check

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  kev-check:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload

    steps:
      - uses: actions/checkout@v4

      - name: Check for KEV vulnerabilities
        uses: ethanolivertroy/kev-checker@v1
        with:
          path: '.'
          format: 'sarif'
          upload-sarif: 'true'
          fail-on-kev: 'true'
```

### Action Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path(s) to scan (space-separated) |
| `format` | `terminal` | Output format: `terminal`, `json`, `sarif` |
| `epss-threshold` | `0` | Only report KEVs with EPSS >= threshold |
| `fail-on-kev` | `true` | Fail the action if KEVs are found |
| `upload-sarif` | `false` | Upload SARIF results to GitHub Code Scanning |

### Action Outputs

| Output | Description |
|--------|-------------|
| `kev-count` | Number of KEV vulnerabilities found |
| `sarif-file` | Path to generated SARIF file |

## Example Output

### Terminal

```
⚠️  KEV VULNERABILITIES FOUND
============================================================

Found 2 KEV vulnerabilities in 2 dependencies

📦 django@3.1.0
   Source: requirements.txt:2

   🔴 CVE-2021-3281
      Django - Django
      Django Directory Traversal Vulnerability
      Added: 2021-12-10 | Due: 2022-06-10
      EPSS: 0.5% (percentile: 25.3%)
      Required Action: Apply updates per vendor instructions.

------------------------------------------------------------

📦 log4j@2.14.1
   Source: pom.xml:15

   🔴 CVE-2021-44228
      Apache - Log4j
      Apache Log4j Remote Code Execution Vulnerability
      Added: 2021-12-10 | Due: 2021-12-24
      EPSS: 97.5% (percentile: 100.0%)
      ⚠️  Known ransomware usage
      Required Action: Apply updates per vendor instructions.

------------------------------------------------------------
```

### JSON

```json
{
  "summary": {
    "total_findings": 2,
    "total_kevs": 2,
    "ransomware_related": 1,
    "affected_packages": 2
  },
  "findings": [
    {
      "package": {
        "name": "django",
        "version": "3.1.0",
        "ecosystem": "PyPI"
      },
      "source_file": "requirements.txt",
      "line": 2,
      "kevs": [
        {
          "cve_id": "CVE-2021-3281",
          "vendor_project": "Django",
          "product": "Django",
          "vulnerability_name": "Django Directory Traversal Vulnerability",
          "description": "...",
          "date_added": "2021-12-10",
          "due_date": "2022-06-10",
          "required_action": "Apply updates per vendor instructions.",
          "ransomware_use": false,
          "epss_score": 0.005,
          "epss_percentile": 0.253
        }
      ]
    }
  ]
}
```

## Data Sources

- **KEV Catalog**: [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) via [cisagov/kev-data](https://github.com/cisagov/kev-data)
- **CVE Mapping**: [OSV (Open Source Vulnerabilities)](https://osv.dev/)
- **EPSS Scores**: [FIRST EPSS API](https://www.first.org/epss/api)

## Why KEV?

Not all vulnerabilities are equal. The CISA KEV catalog specifically tracks vulnerabilities that are:

1. **Actively exploited** - There is evidence of active exploitation in the wild
2. **Affecting federal systems** - These vulnerabilities pose a risk to federal civilian agencies
3. **Remediation-required** - Federal agencies are required to remediate these within specific timeframes

If your dependencies have KEV vulnerabilities, they should be your highest priority to patch.

## License

MIT
