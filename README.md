# Supply Chain Breach Scanner

A portable bash tool that audits installed **npm** and **PyPI** packages against known supply chain breaches, typosquats, and the [OSV.dev](https://osv.dev) vulnerability database.

Runs on developer laptops, CI/CD pipelines, production servers, and containers — macOS and Linux.

## How It Works

The scanner runs four layers of checks:

| Layer | What it does | Network required |
|-------|-------------|-----------------|
| **Malicious package list** | Checks installed packages against a curated list of known-compromised packages (event-stream, ua-parser-js, ctx, etc.) | No |
| **npm audit** | Finds `package-lock.json` files and runs `npm audit` on each project | Yes |
| **OSV.dev API** | Queries every globally-installed npm package and pip package against Google's OSV vulnerability database | Yes |
| **Virtual environment scan** | Discovers Python virtualenvs in scan directories and audits their packages | Yes |

If `pip-audit` is installed, it is preferred over raw OSV queries for PyPI packages. The scanner falls back gracefully when tools or network are unavailable.

## Requirements

**Required:**
- Bash 4.0+
- Python 3.x
- curl

**Optional (auto-detected):**
- npm (for npm scanning)
- pip / pip3 (for PyPI scanning)
- [pip-audit](https://github.com/pypa/pip-audit) (preferred over raw OSV queries)

## Quick Start

```bash
# Clone or copy the script
chmod +x supply_chain_audit.sh

# Full scan on your machine
./supply_chain_audit.sh

# Scan a specific project
./supply_chain_audit.sh -d /path/to/project

# CI pipeline (JSON output, fails on vulnerabilities)
./supply_chain_audit.sh --format json --quiet
```

## Usage

```
./supply_chain_audit.sh [OPTIONS]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --dir DIR` | Directory to scan (repeatable) | Auto-detect |
| `-f, --format FORMAT` | Output format: `text` or `json` | `text` |
| `--depth N` | Max directory search depth | `5` |
| `--npm-only` | Only scan npm packages | — |
| `--pypi-only` | Only scan PyPI packages | — |
| `--offline` | Skip OSV.dev API queries (malicious-list only) | — |
| `--max-projects N` | Max npm projects to audit | `50` |
| `-q, --quiet` | Only print vulnerabilities and errors | — |
| `-v, --verbose` | Enable debug output | — |
| `--no-color` | Disable colored output | — |
| `--report-dir DIR` | Directory for report files | `~/.supply_chain_audit` |
| `-h, --help` | Show help | — |
| `--version` | Show version | — |

## Environment Examples

### Developer Machine

```bash
# Full scan — discovers projects under $HOME
./supply_chain_audit.sh

# Verbose scan of a specific workspace
./supply_chain_audit.sh -d ~/workspace/myapp -v
```

### CI/CD Pipeline

```bash
# JSON output for parsing, non-zero exit code gates the build
./supply_chain_audit.sh --format json --quiet -d .

# GitHub Actions example
- name: Supply chain audit
  run: ./supply_chain_audit.sh --format json --quiet -d .
  continue-on-error: false
```

### Production Server

```bash
# Scan deployed application directories
./supply_chain_audit.sh -d /opt/myapp -d /srv/api

# Air-gapped server (no internet access)
./supply_chain_audit.sh --offline -d /opt/myapp
```

### Docker Container

```bash
# Inside a container, auto-detects /app, /opt, /srv
./supply_chain_audit.sh

# Or target the app directory explicitly
./supply_chain_audit.sh -d /app --format json --quiet
```

```dockerfile
# Add to a Dockerfile for build-time scanning
COPY supply_chain_audit.sh /usr/local/bin/
RUN supply_chain_audit.sh -d /app --quiet
```

### Multiple Projects on a Shared Server

```bash
./supply_chain_audit.sh \
  -d /srv/frontend \
  -d /srv/api \
  -d /home/deploy/workers \
  --report-dir /var/log/supply-chain-audit
```

## Output

### Text (default)

Color-coded terminal output with severity levels:

```
[VULN] Found 3 vulnerability(ies) in /opt/myapp
[VULN]     high: 2
[VULN]     moderate: 1
[ OK ] corepack@0.32.0
[WARN] Cannot reach OSV.dev API — running in offline mode
```

Colors are automatically disabled when output is piped or when running in CI. Force disable with `--no-color` or `NO_COLOR=1`.

### JSON (`--format json`)

```json
{
  "version": "2.0.0",
  "timestamp": "2026-05-18T12:00:00Z",
  "machine": {
    "hostname": "prod-web-01",
    "os": "Linux",
    "distro": "ubuntu 22.04",
    "arch": "x86_64",
    "is_container": false,
    "is_ci": false
  },
  "summary": {
    "packages_scanned": 142,
    "vulnerabilities_found": 3,
    "scan_errors": 0,
    "exit_code": 1
  },
  "vulnerabilities": [
    {
      "ecosystem": "npm",
      "package": "lodash",
      "version": "4.17.20",
      "vuln_id": "GHSA-xxxx",
      "severity": "high",
      "summary": "Prototype pollution in lodash",
      "source": "npm-audit:/opt/myapp"
    }
  ]
}
```

### Reports

Every run saves a plain-text report to `~/.supply_chain_audit/` (or the directory set by `--report-dir`). Reports are named with the hostname and timestamp:

```
audit_prod-web-01_20260518_120000.txt
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities found |
| `1` | One or more vulnerabilities found |
| `2` | Missing required dependency (Python 3 or curl) |

Use exit code `1` to gate CI/CD pipelines — the build fails if any vulnerability is detected.

## Platform Compatibility

| Platform | Tested |
|----------|--------|
| macOS (Apple Silicon & Intel) | Yes |
| Ubuntu / Debian | Yes |
| CentOS / RHEL / Amazon Linux | Yes |
| Alpine Linux (containers) | Yes |
| GitHub Actions runners | Yes |
| GitLab CI runners | Yes |
| Jenkins agents | Yes |
| Docker containers | Yes |

The scanner auto-detects:
- **Python**: tries `python3` then `python`, verifies it is Python 3
- **pip**: tries `pip3` then `pip`, verifies it targets Python 3
- **Containers**: checks for `/.dockerenv` and cgroup markers
- **CI/CD**: detects GitHub Actions, GitLab CI, Jenkins, CircleCI, Buildkite, Travis, and CodeBuild

## Offline / Air-Gapped Mode

For servers without internet access, use `--offline` to skip all OSV.dev API calls. The scanner still checks installed packages against the built-in malicious package list.

```bash
./supply_chain_audit.sh --offline -d /opt/myapp
```

The malicious package list is embedded in the script and covers high-profile incidents. Update the script periodically to get new entries.

## Known Malicious Packages Checked

The scanner includes a curated list of historically compromised packages:

**npm:** event-stream, ua-parser-js, coa, rc, colors, faker, node-ipc, everything, @lottiefiles/lottie-player, crypto-encrypt-ts, pdf-to-office, and others.

**PyPI:** ctx, colourama, python3-dateutil, jeIlyfish, pycryptoenv, pycryptoconf, jarkascryptolib, paborern, and others.

This list covers hijacked packages, typosquats, protestware, and dependency confusion attacks.

## License

MIT
