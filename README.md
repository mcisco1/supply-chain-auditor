# Supply Chain Dependency Auditor

A production-grade security tool that scans Python and Node.js codebases for dependency vulnerabilities. It extracts all dependencies recursively, cross-references them against three major vulnerability databases (NVD, OSV, and GitHub Advisory), maps the full dependency tree, calculates risk scores, and produces an interactive HTML dashboard report. 

# 2 TESTS WITH FOLDERS INCLUDED TO SEE HOW IT WORKS

---

# Features 

- **Multi-Ecosystem Parsing** — Supports `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.py`, `setup.cfg`, `package.json`, `package-lock.json`, and `yarn.lock`
- **Recursive Dependency Resolution** — Walks transitive dependencies up to four levels deep using the PyPI and npm registry APIs
- **Triple-Source Vulnerability Checking** — Queries the NVD (National Vulnerability Database), OSV (Open Source Vulnerabilities), and GitHub Advisory Database in parallel
- **CVSS-Based Risk Scoring** — Calculates per-package and overall risk scores (0–10) weighted by vulnerability severity, dependency depth, outdated status, and license risk
- **Interactive HTML Dashboard** — Generates a self-contained HTML report with severity charts, a D3.js dependency tree visualization, sortable/filterable package inventory, detailed vulnerability cards, and actionable recommendations
- **JSON Export** — Machine-readable output for integration with CI/CD pipelines and downstream tooling
- **Rich Terminal Output** — Color-coded CLI interface with progress bars and summary tables (gracefully degrades without the `rich` library)

---

## Installation

```bash
git clone https://github.com/your-username/supply-chain-auditor.git
cd supply-chain-auditor
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

**Requirements:** Python 3.9+

---

## Usage

### Basic Scan

```bash
python scan.py /path/to/your/project
```

This scans the target directory, resolves dependencies, runs vulnerability checks, and writes `audit_report.html` in the current directory.

### Output Formats

```bash
# HTML report (default)
python scan.py ./my-project --format html --output report.html

# JSON export
python scan.py ./my-project --format json --output results.json

# Both formats
python scan.py ./my-project --format both --output audit_report
```

### Demo with Sample Project

A sample project with intentionally outdated dependencies is included for testing:

```bash
python scan.py ./sample_project
```

Open the generated `audit_report.html` in any browser to see the full dashboard.

### CLI Reference

```
usage: scan [-h] [-f {html,json,both}] [-o OUTPUT] [--verbose] [--version] target

positional arguments:
  target                Path to the project directory to scan

options:
  -h, --help            show this help message and exit
  -f, --format          Output report format: html, json, both (default: html)
  -o, --output          Output file path
  --verbose, -v         Enable debug logging
  --version             show version and exit
```

---

# How It Works

### 1. Dependency Extraction

The parser module walks the target directory and reads every recognized dependency manifest. It normalizes package names and version specifiers across all file formats, deduplicating where multiple files reference the same package.

### 2. Recursive Resolution

Each discovered package is resolved against the PyPI JSON API (Python) or the npm registry (Node.js). The resolver fetches metadata for each package — latest version, license, description — then recursively resolves sub-dependencies. A configurable depth limit (default: 4) and visited-set prevent infinite loops in circular dependency chains. Resolution runs in parallel using a thread pool for speed.

### 3. Vulnerability Analysis

Every resolved package is checked against three databases concurrently:

| Database | Endpoint | What It Covers |
|---|---|---|
| **OSV** | `api.osv.dev/v1/query` | Aggregated open-source vulnerability data across ecosystems |
| **NVD** | `services.nvd.nist.gov/rest/json/cves/2.0` | NIST's comprehensive CVE catalog with CVSS scores |
| **GitHub Advisory** | `api.github.com/advisories` | GitHub's curated security advisories |

Results are deduplicated by vulnerability ID and sorted by severity.

### 4. Risk Scoring

Each package receives a composite risk score (0–10) based on:

- **Vulnerability severity** — Weighted by CVSS score and severity class (critical=3×, high=2×, medium=1×, low=0.4×)
- **Outdated status** — Packages behind their latest release receive a penalty
- **Dependency depth** — Transitive dependencies are harder to patch, so deeper packages get a slight bump
- **License risk** — Restrictive or unknown licenses add a small risk factor

The overall project score uses a weighted aggregation biased toward the most severe findings.

### 5. Report Generation

The HTML report is a fully self-contained file (no server required) that uses embedded JavaScript to render:

- Executive risk gauge and KPI cards
- Severity distribution bars and composition donut chart
- Interactive D3.js dependency tree
- Sortable, filterable package inventory table
- Detailed vulnerability cards with references and fix versions
- Prioritized remediation recommendations

---

## Project Structure

```
supply-chain-auditor/
├── auditor/
│   ├── __init__.py          # Package metadata
│   ├── models.py            # Data models (Dependency, Vulnerability, ScanResult)
│   ├── parsers.py           # Dependency file parsers for Python and Node
│   ├── resolver.py          # Recursive dependency tree resolution
│   ├── vulnerability.py     # NVD, OSV, GitHub Advisory API integrations
│   ├── risk.py              # Risk scoring engine
│   └── report.py            # HTML and JSON report generation
├── templates/
│   └── report_template.html # Interactive dashboard template
├── sample_project/          # Demo project with known-vulnerable packages
│   ├── requirements.txt
│   └── package.json
├── scan.py                  # CLI entry point
├── setup.py                 # Package installation config
├── requirements.txt         # Tool dependencies
└── README.md
```

---

## API Rate Limits

- **OSV**: No authentication needed. No strict rate limit.
- **NVD**: Public API allows ~5 requests/30 seconds without a key. The tool enforces a 0.7s delay between NVD calls. For higher throughput, set the `NVD_API_KEY` environment variable.
- **GitHub Advisory**: Unauthenticated access allows 60 requests/hour. Set `GITHUB_TOKEN` for higher limits.

---

## Extending the Tool

**Adding a new parser:** Create a parsing function in `parsers.py` that returns a list of `(name, version)` tuples, then register it in the `PYTHON_PARSERS` or `NODE_PARSERS` dictionary.

**Adding a vulnerability source:** Implement a `check_<source>(name, version, ecosystem)` function in `vulnerability.py` that returns a list of `Vulnerability` objects, then call it from `check_package()`.

**CI/CD Integration:** Use the JSON output format and parse the `overall_risk_score` field to set quality gates:

```bash
python scan.py ./src --format json --output results.json
RISK=$(python -c "import json; print(json.load(open('results.json'))['overall_risk_score'])")
if (( $(echo "$RISK > 7.0" | bc -l) )); then
  echo "FAIL: Risk score $RISK exceeds threshold"
  exit 1
fi
```

---

## License

MIT

# PLEASE NOTE, some areas of README are written by AI to speed things up for me. If you notice any issues, please reach out to me so I can fix in potentially newer releases
