#!/usr/bin/env bash
set -euo pipefail

readonly VERSION="2.0.0"
readonly OSV_API="https://api.osv.dev/v1/query"
readonly OSV_BATCH_API="https://api.osv.dev/v1/querybatch"

# ──────────────────────────────────────
#  DEFAULTS (overridden by CLI flags)
# ──────────────────────────────────────
OUTPUT_FORMAT="text"           # text | json
SCAN_NPM=true
SCAN_PYPI=true
SCAN_DIRS=()                   # directories to scan for projects; empty = auto-detect
SCAN_DEPTH=5
REPORT_DIR="${HOME}/.supply_chain_audit"
SKIP_OSV=false                 # offline/air-gapped mode
VERBOSE=false
QUIET=false
MAX_PROJECTS=50
PIP_CMD=""
PYTHON_CMD=""

VULNS_FOUND=0
PACKAGES_SCANNED=0
SCAN_ERRORS=0
JSON_RESULTS="[]"

# ──────────────────────────────────────
#  PLATFORM DETECTION
# ──────────────────────────────────────
detect_platform() {
    OS_TYPE="$(uname -s)"
    ARCH="$(uname -m)"
    HOSTNAME_STR="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo 'unknown')"
    KERNEL="$(uname -r 2>/dev/null || echo 'unknown')"

    case "$OS_TYPE" in
        Linux)
            if [[ -f /etc/os-release ]]; then
                DISTRO=$(. /etc/os-release && echo "${ID:-linux} ${VERSION_ID:-}")
            elif [[ -f /etc/redhat-release ]]; then
                DISTRO=$(cat /etc/redhat-release)
            else
                DISTRO="linux"
            fi
            ;;
        Darwin) DISTRO="macOS $(sw_vers -productVersion 2>/dev/null || echo '')" ;;
        *)      DISTRO="$OS_TYPE" ;;
    esac

    IS_CONTAINER=false
    if [[ -f /.dockerenv ]] || grep -qsE '(docker|lxc|containerd|kubepods)' /proc/1/cgroup 2>/dev/null; then
        IS_CONTAINER=true
    fi

    IS_CI=false
    if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" || -n "${JENKINS_URL:-}" || \
          -n "${GITLAB_CI:-}" || -n "${CIRCLECI:-}" || -n "${BUILDKITE:-}" || \
          -n "${TRAVIS:-}" || -n "${CODEBUILD_BUILD_ID:-}" ]]; then
        IS_CI=true
    fi
}

# ──────────────────────────────────────
#  COLOR SUPPORT
# ──────────────────────────────────────
setup_colors() {
    if [[ "$OUTPUT_FORMAT" == "json" ]] || [[ ! -t 1 ]] || [[ "${NO_COLOR:-}" == "1" ]]; then
        RED="" YELLOW="" GREEN="" CYAN="" BOLD="" NC=""
    else
        RED='\033[0;31m'
        YELLOW='\033[1;33m'
        GREEN='\033[0;32m'
        CYAN='\033[0;36m'
        BOLD='\033[1m'
        NC='\033[0m'
    fi
}

# ──────────────────────────────────────
#  LOGGING
# ──────────────────────────────────────
REPORT_FILE=""

init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="/tmp/supply_chain_audit"
    mkdir -p "$REPORT_DIR"
    REPORT_FILE="${REPORT_DIR}/audit_${HOSTNAME_STR}_$(date +%Y%m%d_%H%M%S).txt"
    : > "$REPORT_FILE"
}

_log() {
    local level="$1"; shift
    if [[ "$QUIET" == true && "$level" != "VULN" && "$level" != "CRIT" ]]; then
        return
    fi

    local color=""
    case "$level" in
        INFO) color="$CYAN"   ;;
        WARN) color="$YELLOW" ;;
        VULN) color="$RED"    ;;
        OK)   color="$GREEN"  ;;
        CRIT) color="$RED"    ;;
    esac

    local msg
    msg="[${level}] $*"
    echo -e "${color}${msg}${NC}"
    [[ -n "$REPORT_FILE" ]] && echo "$msg" >> "$REPORT_FILE"
}

log()    { _log "INFO" "$@"; }
warn()   { _log "WARN" "$@"; }
vuln()   { _log "VULN" "$@"; }
ok()     { _log "OK"   "$@"; }
crit()   { _log "CRIT" "$@"; }
debug()  { [[ "$VERBOSE" == true ]] && _log "INFO" "(debug) $*" || true; }

header() {
    if [[ "$OUTPUT_FORMAT" != "json" ]]; then
        echo ""
        _log "INFO" "════════════════════════════════════════"
        _log "INFO" "  $*"
        _log "INFO" "════════════════════════════════════════"
    fi
}

# ──────────────────────────────────────
#  JSON HELPERS
# ──────────────────────────────────────
json_add_vuln() {
    local ecosystem="$1" package="$2" version="$3" vuln_id="$4" severity="$5" summary="$6" source="$7"
    JSON_RESULTS=$($PYTHON_CMD -c "
import json, sys
results = json.loads(sys.stdin.read())
results.append({
    'ecosystem': '$ecosystem',
    'package': '$package',
    'version': '$version',
    'vuln_id': '$vuln_id',
    'severity': '$severity',
    'summary': $(printf '%s' "$summary" | $PYTHON_CMD -c "import json,sys; print(json.dumps(sys.stdin.read()))"),
    'source': '$source'
})
print(json.dumps(results))
" <<< "$JSON_RESULTS" 2>/dev/null) || true
}

emit_json_report() {
    $PYTHON_CMD -c "
import json, sys
results = json.loads(sys.stdin.read())
report = {
    'version': '$VERSION',
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'machine': {
        'hostname': '$HOSTNAME_STR',
        'os': '$OS_TYPE',
        'distro': '$DISTRO',
        'arch': '$ARCH',
        'is_container': $( [[ "$IS_CONTAINER" == true ]] && echo 'True' || echo 'False' ),
        'is_ci': $( [[ "$IS_CI" == true ]] && echo 'True' || echo 'False' )
    },
    'summary': {
        'packages_scanned': $PACKAGES_SCANNED,
        'vulnerabilities_found': $VULNS_FOUND,
        'scan_errors': $SCAN_ERRORS,
        'exit_code': $( [[ \$VULNS_FOUND -gt 0 ]] && echo 1 || echo 0 )
    },
    'vulnerabilities': results
}
print(json.dumps(report, indent=2))
" <<< "$JSON_RESULTS"
}

# ──────────────────────────────────────
#  DEPENDENCY DETECTION
# ──────────────────────────────────────
find_python() {
    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            local ver
            ver=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null) || continue
            if [[ "$ver" -ge 3 ]]; then
                PYTHON_CMD="$cmd"
                debug "Using Python: $cmd ($("$cmd" --version 2>&1))"
                return 0
            fi
        fi
    done
    return 1
}

find_pip() {
    for cmd in pip3 pip; do
        if command -v "$cmd" &>/dev/null; then
            local ver
            ver=$("$cmd" --version 2>/dev/null | grep -oE 'python [0-9]+' | grep -oE '[0-9]+') || continue
            if [[ "$ver" -ge 3 ]]; then
                PIP_CMD="$cmd"
                debug "Using pip: $cmd ($("$cmd" --version 2>&1))"
                return 0
            fi
        fi
    done
    return 1
}

has_cmd() { command -v "$1" &>/dev/null; }

check_network() {
    if [[ "$SKIP_OSV" == true ]]; then
        warn "Offline mode — skipping OSV.dev queries"
        return 1
    fi
    if ! curl -s --max-time 5 -o /dev/null "https://api.osv.dev/v1" 2>/dev/null; then
        warn "Cannot reach OSV.dev API — running in offline mode"
        SKIP_OSV=true
        return 1
    fi
    return 0
}

# ──────────────────────────────────────
#  OSV QUERY
# ──────────────────────────────────────
query_osv() {
    [[ "$SKIP_OSV" == true ]] && return 1

    local ecosystem="$1" package="$2" version="$3"
    local payload
    payload=$($PYTHON_CMD -c "
import json
print(json.dumps({
    'version': '$version',
    'package': {'name': '$package', 'ecosystem': '$ecosystem'}
}))")

    local response
    response=$(curl -s --max-time 10 -X POST "$OSV_API" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null) || return 1

    local vuln_count
    vuln_count=$(echo "$response" | $PYTHON_CMD -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(len(data.get('vulns', [])))
except:
    print(0)
" 2>/dev/null)

    if [[ "$vuln_count" -gt 0 ]]; then
        echo "$response" | $PYTHON_CMD -c "
import sys, json
data = json.load(sys.stdin)
for v in data.get('vulns', []):
    vid = v.get('id', 'N/A')
    summary = v.get('summary', 'No summary available')
    severity = 'UNKNOWN'
    for s in v.get('severity', []):
        severity = s.get('score', severity)
    aliases = ', '.join(v.get('aliases', [])[:3]) or 'None'
    print(f'  {vid} | {summary[:80]}')
    print(f'    Severity: {severity} | Aliases: {aliases}')
" 2>/dev/null
        return 2
    fi
    return 0
}

query_osv_batch() {
    [[ "$SKIP_OSV" == true ]] && return 1

    local ecosystem="$1"
    shift
    local -a packages=("$@")

    local batch_json
    batch_json=$($PYTHON_CMD -c "
import json, sys
queries = []
for line in sys.stdin:
    line = line.strip()
    if not line or '==' not in line:
        continue
    pkg, ver = line.rsplit('==', 1)
    queries.append({
        'version': ver,
        'package': {'name': pkg, 'ecosystem': '$ecosystem'}
    })
print(json.dumps({'queries': queries}))
" <<< "$(printf '%s\n' "${packages[@]}")" 2>/dev/null)

    curl -s --max-time 60 -X POST "$OSV_BATCH_API" \
        -H "Content-Type: application/json" \
        -d "$batch_json" 2>/dev/null
}

# ──────────────────────────────────────
#  KNOWN MALICIOUS PACKAGES
# ──────────────────────────────────────
check_known_malicious() {
    header "Known Malicious Package Patterns"

    local -a npm_malicious=(
        "event-stream"
        "ua-parser-js"
        "coa"
        "rc"
        "colors"
        "faker"
        "peacenotwar"
        "node-ipc"
        "es5-ext"
        "everything"
        "@lottiefiles/lottie-player"
        "crypto-encrypt-ts"
        "pdf-to-office"
        "rand-user-agent"
        "lottie-player"
    )

    local -a pypi_malicious=(
        "ctx"
        "phpass"
        "colourama"
        "python-binance"
        "requesocks"
        "python3-dateutil"
        "jeIlyfish"
        "libpeshka"
        "ultra_type"
        "pycryptoenv"
        "pycryptoconf"
        "crytic-compilers"
        "free-net-vpn"
        "jarkascryptolib"
        "paborern"
        "aaborern"
    )

    # --- npm ---
    if [[ "$SCAN_NPM" == true ]] && has_cmd npm; then
        log "Checking installed npm packages against malicious list..."
        local npm_global=""
        npm_global=$(npm list -g --depth=0 --parseable 2>/dev/null) || true

        for pkg in "${npm_malicious[@]}"; do
            if echo "$npm_global" | grep -q "/${pkg}$" 2>/dev/null; then
                vuln "MALICIOUS npm package installed globally: $pkg"
                json_add_vuln "npm" "$pkg" "any" "MALICIOUS" "CRITICAL" "Known malicious package" "malicious-list"
                VULNS_FOUND=$((VULNS_FOUND + 1))
            fi
        done

        local -a search_dirs=("${SCAN_DIRS[@]}")
        [[ ${#search_dirs[@]} -eq 0 ]] && search_dirs=(".")

        for dir in "${search_dirs[@]}"; do
            [[ -d "$dir/node_modules" ]] || continue
            for pkg in "${npm_malicious[@]}"; do
                if [[ -d "$dir/node_modules/$pkg" ]]; then
                    vuln "MALICIOUS npm package in $dir/node_modules: $pkg"
                    json_add_vuln "npm" "$pkg" "any" "MALICIOUS" "CRITICAL" "Known malicious package" "malicious-list"
                    VULNS_FOUND=$((VULNS_FOUND + 1))
                fi
            done
        done
    fi

    # --- pypi ---
    if [[ "$SCAN_PYPI" == true ]] && [[ -n "$PIP_CMD" ]]; then
        log "Checking installed PyPI packages against malicious list..."
        local pip_pkgs=""
        pip_pkgs=$($PIP_CMD list --format=freeze 2>/dev/null | cut -d= -f1 | tr '[:upper:]' '[:lower:]') || true

        for pkg in "${pypi_malicious[@]}"; do
            local pkg_lower
            pkg_lower=$(echo "$pkg" | tr '[:upper:]' '[:lower:]')
            if echo "$pip_pkgs" | grep -qx "$pkg_lower" 2>/dev/null; then
                vuln "MALICIOUS PyPI package installed: $pkg"
                json_add_vuln "PyPI" "$pkg" "any" "MALICIOUS" "CRITICAL" "Known malicious package" "malicious-list"
                VULNS_FOUND=$((VULNS_FOUND + 1))
            fi
        done
    fi

    ok "Known malicious package check complete"
}

# ──────────────────────────────────────
#  NPM GLOBAL PACKAGES via OSV
# ──────────────────────────────────────
audit_npm_global() {
    header "NPM Global Packages (OSV.dev)"

    if ! has_cmd npm; then
        warn "npm not found — skipping"
        return
    fi

    local pkgs=""
    pkgs=$(npm list -g --depth=0 --json 2>/dev/null | $PYTHON_CMD -c "
import sys, json
try:
    data = json.load(sys.stdin)
    deps = data.get('dependencies', {})
    for name, info in deps.items():
        ver = info.get('version', '')
        if ver:
            print(f'{name} {ver}')
except:
    pass
" 2>/dev/null) || true

    if [[ -z "$pkgs" ]]; then
        log "No global npm packages found"
        return
    fi

    while IFS=' ' read -r pkg ver; do
        [[ -z "$pkg" || -z "$ver" ]] && continue
        PACKAGES_SCANNED=$((PACKAGES_SCANNED + 1))
        local result=""
        result=$(query_osv "npm" "$pkg" "$ver" 2>/dev/null) || true
        local rc=${PIPESTATUS[0]:-$?}

        if [[ $rc -eq 2 ]]; then
            vuln "$pkg@$ver — VULNERABLE"
            [[ -n "$result" ]] && echo "$result" >> "$REPORT_FILE"
            [[ -n "$result" && "$QUIET" != true ]] && echo "$result"
            VULNS_FOUND=$((VULNS_FOUND + 1))
        elif [[ $rc -eq 0 ]]; then
            ok "$pkg@$ver"
        else
            debug "$pkg@$ver — could not query OSV"
        fi
    done <<< "$pkgs"
}

# ──────────────────────────────────────
#  NPM PROJECT AUDIT
# ──────────────────────────────────────
audit_npm_projects() {
    header "NPM Project Audit (npm audit)"

    if ! has_cmd npm; then
        warn "npm not found — skipping npm project audit"
        return
    fi

    local found_projects=0
    local -a search_roots=("${SCAN_DIRS[@]}")

    if [[ ${#search_roots[@]} -eq 0 ]]; then
        if [[ "$IS_CI" == true || "$IS_CONTAINER" == true ]]; then
            search_roots=("/app" "/opt" "/srv" "/home" "$(pwd)")
        else
            search_roots=("$HOME")
        fi
    fi

    local lockfiles=""
    for root in "${search_roots[@]}"; do
        [[ -d "$root" ]] || continue
        debug "Searching for npm projects in: $root (depth=$SCAN_DEPTH)"
        local found=""
        found=$(find "$root" -maxdepth "$SCAN_DEPTH" -name "package-lock.json" \
            -not -path "*/node_modules/*" \
            -not -path "*/.cache/*" \
            -not -path "*/Library/*" \
            -not -path "*/.npm/*" \
            -not -path "*/.nvm/*" \
            2>/dev/null) || true
        [[ -n "$found" ]] && lockfiles="${lockfiles}${found}"$'\n'
    done

    lockfiles=$(echo "$lockfiles" | grep -v '^$' | head -"$MAX_PROJECTS")

    while IFS= read -r lockfile; do
        [[ -z "$lockfile" ]] && continue
        local project_dir
        project_dir=$(dirname "$lockfile")
        found_projects=$((found_projects + 1))

        log "Auditing project: ${project_dir}"

        local audit_output=""
        audit_output=$(cd "$project_dir" && npm audit --json 2>/dev/null) || true

        if [[ -z "$audit_output" ]]; then
            debug "npm audit returned empty output for $project_dir"
            SCAN_ERRORS=$((SCAN_ERRORS + 1))
            continue
        fi

        local vuln_total=0
        vuln_total=$(echo "$audit_output" | $PYTHON_CMD -c "
import sys, json
try:
    data = json.load(sys.stdin)
    v = data.get('metadata', {}).get('vulnerabilities', {})
    print(sum(v.values()) if isinstance(v, dict) else 0)
except:
    print(0)
" 2>/dev/null) || vuln_total=0

        if [[ "$vuln_total" -gt 0 ]]; then
            vuln "Found $vuln_total vulnerability(ies) in $project_dir"
            VULNS_FOUND=$((VULNS_FOUND + vuln_total))

            echo "$audit_output" | $PYTHON_CMD -c "
import sys, json
try:
    data = json.load(sys.stdin)
    v = data.get('metadata', {}).get('vulnerabilities', {})
    for sev, count in sorted(v.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            print(f'    {sev}: {count}')
except:
    pass
" 2>/dev/null | while IFS= read -r line; do
                _log "VULN" "$line"
            done

            echo "$audit_output" | $PYTHON_CMD -c "
import json, sys
try:
    data = json.load(sys.stdin)
    vulns = data.get('vulnerabilities', {})
    for name, info in vulns.items():
        sev = info.get('severity', 'unknown')
        via_list = [v.get('title','') for v in info.get('via', []) if isinstance(v, dict)]
        title = via_list[0] if via_list else 'N/A'
        print(f'{name}|||{info.get(\"range\",\"\")}|||{sev}|||{title}')
except:
    pass
" 2>/dev/null | while IFS='|||' read -r pkg range sev title; do
                json_add_vuln "npm" "$pkg" "$range" "npm-audit" "$sev" "$title" "npm-audit:$project_dir"
            done
        else
            ok "No known vulnerabilities in $project_dir"
        fi
    done <<< "$lockfiles"

    if [[ "$found_projects" -eq 0 ]]; then
        log "No npm projects with lock files found in scan directories"
    else
        log "Scanned $found_projects npm project(s)"
    fi
}

# ──────────────────────────────────────
#  PIP-AUDIT
# ──────────────────────────────────────
audit_pip_tool() {
    header "PyPI Audit (pip-audit)"

    if ! has_cmd pip-audit; then
        log "pip-audit not installed — will use OSV.dev API instead"
        debug "Install it with: $PIP_CMD install pip-audit"
        return 1
    fi

    local audit_output=""
    audit_output=$(pip-audit --format=json 2>/dev/null) || true

    if [[ -z "$audit_output" ]]; then
        warn "pip-audit returned empty output"
        SCAN_ERRORS=$((SCAN_ERRORS + 1))
        return 1
    fi

    local vuln_count=0
    vuln_count=$(echo "$audit_output" | $PYTHON_CMD -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(sum(len(d.get('vulns',[])) for d in data if d.get('vulns')))
except:
    print(0)
" 2>/dev/null) || vuln_count=0

    if [[ "$vuln_count" -gt 0 ]]; then
        vuln "pip-audit found $vuln_count vulnerability(ies):"
        VULNS_FOUND=$((VULNS_FOUND + vuln_count))

        echo "$audit_output" | $PYTHON_CMD -c "
import sys, json
data = json.load(sys.stdin)
for pkg in data:
    if pkg.get('vulns'):
        name = pkg['name']
        ver = pkg['version']
        for v in pkg['vulns']:
            vid = v.get('id', 'N/A')
            fix = v.get('fix_versions', ['no fix'])
            print(f'    {name}=={ver}  {vid}  fix: {\", \".join(fix)}')
" 2>/dev/null | while IFS= read -r line; do
            _log "VULN" "$line"
        done
    else
        ok "pip-audit: no known vulnerabilities"
    fi
    return 0
}

# ──────────────────────────────────────
#  PYPI via OSV BATCH API
# ──────────────────────────────────────
audit_pypi_osv() {
    header "PyPI Installed Packages (OSV.dev)"

    if [[ -z "$PIP_CMD" ]]; then
        warn "pip not found — skipping PyPI audit"
        return
    fi

    local pkgs=""
    pkgs=$($PIP_CMD list --format=freeze 2>/dev/null | grep -v '^\-' | grep '==' | head -500) || true

    if [[ -z "$pkgs" ]]; then
        log "No pip packages found"
        return
    fi

    local total
    total=$(echo "$pkgs" | wc -l | tr -d ' ')
    log "Scanning $total PyPI packages against OSV.dev..."

    local pkg_list=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pkg_list+=("$line")
        PACKAGES_SCANNED=$((PACKAGES_SCANNED + 1))
    done <<< "$pkgs"

    local batch_response=""
    batch_response=$(query_osv_batch "PyPI" "${pkg_list[@]}") || true

    if [[ -z "$batch_response" ]]; then
        warn "OSV batch query failed — falling back to individual queries"
        for entry in "${pkg_list[@]}"; do
            local pkg="${entry%%==*}"
            local ver="${entry##*==}"
            local result=""
            result=$(query_osv "PyPI" "$pkg" "$ver" 2>/dev/null) || true
            local rc=$?
            if [[ $rc -eq 2 ]]; then
                vuln "$pkg==$ver — VULNERABLE"
                [[ -n "$result" && "$QUIET" != true ]] && echo "$result"
                VULNS_FOUND=$((VULNS_FOUND + 1))
            fi
        done
        return
    fi

    $PYTHON_CMD -c "
import json, sys

pkg_lines = []
for line in sys.stdin:
    line = line.strip()
    if line:
        pkg_lines.append(line)

try:
    response = json.loads('''$(echo "$batch_response" | $PYTHON_CMD -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null | sed 's/^"//;s/"$//')''')
except:
    response = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {'results': []}

results = response.get('results', [])
vuln_count = 0

for i, result in enumerate(results):
    vulns = result.get('vulns', [])
    if vulns and i < len(pkg_lines):
        pkg = pkg_lines[i]
        vuln_count += len(vulns)
        print(f'VULN|{pkg}|{len(vulns)}')
        for v in vulns[:5]:
            vid = v.get('id', 'N/A')
            summary = v.get('summary', 'No summary')[:80]
            aliases = ', '.join(v.get('aliases', [])[:3]) or 'None'
            print(f'DETAIL|{vid}|{summary}|{aliases}')

if vuln_count == 0:
    print('CLEAN|0|0')

print(f'TOTAL|{vuln_count}|0')
" <<< "$(printf '%s\n' "${pkg_list[@]}")" 2>/dev/null | while IFS='|' read -r tag f1 f2 f3; do
        case "$tag" in
            VULN)   vuln "$f1 — $f2 vulnerability(ies)" ;;
            DETAIL) echo "      $f1: $f2" >> "$REPORT_FILE"
                    [[ "$QUIET" != true ]] && echo "      $f1: $f2 (aliases: $f3)" ;;
            CLEAN)  ok "No known vulnerabilities in PyPI packages" ;;
            TOTAL)
                if [[ "$f1" -gt 0 ]]; then
                    VULNS_FOUND=$((VULNS_FOUND + f1))
                fi
                ;;
        esac
    done
}

# ──────────────────────────────────────
#  VIRTUAL ENV DETECTION
# ──────────────────────────────────────
scan_virtualenvs() {
    header "Python Virtual Environments"

    local -a search_roots=("${SCAN_DIRS[@]}")
    [[ ${#search_roots[@]} -eq 0 ]] && search_roots=("$(pwd)")

    local found_venvs=0

    for root in "${search_roots[@]}"; do
        [[ -d "$root" ]] || continue

        while IFS= read -r activate_script; do
            [[ -z "$activate_script" ]] && continue
            local venv_dir
            venv_dir=$(dirname "$(dirname "$activate_script")")
            found_venvs=$((found_venvs + 1))

            local venv_pip="${venv_dir}/bin/pip"
            [[ -x "$venv_pip" ]] || venv_pip="${venv_dir}/Scripts/pip.exe"
            [[ -x "$venv_pip" ]] || continue

            log "Scanning virtualenv: $venv_dir"

            local venv_pkgs=""
            venv_pkgs=$("$venv_pip" list --format=freeze 2>/dev/null | grep '==' | head -500) || continue

            local venv_count
            venv_count=$(echo "$venv_pkgs" | wc -l | tr -d ' ')
            debug "  $venv_count packages in $venv_dir"

            if [[ "$SKIP_OSV" == false ]] && [[ -n "$venv_pkgs" ]]; then
                local venv_pkg_list=()
                while IFS= read -r line; do
                    [[ -z "$line" ]] && continue
                    venv_pkg_list+=("$line")
                    PACKAGES_SCANNED=$((PACKAGES_SCANNED + 1))
                done <<< "$venv_pkgs"

                local venv_batch=""
                venv_batch=$(query_osv_batch "PyPI" "${venv_pkg_list[@]}") || true

                if [[ -n "$venv_batch" ]]; then
                    local venv_vulns
                    venv_vulns=$($PYTHON_CMD -c "
import json, sys
data = json.loads(sys.stdin.read())
count = sum(1 for r in data.get('results', []) if r.get('vulns'))
print(count)
" <<< "$venv_batch" 2>/dev/null) || venv_vulns=0

                    if [[ "$venv_vulns" -gt 0 ]]; then
                        vuln "Found $venv_vulns vulnerable package(s) in $venv_dir"
                        VULNS_FOUND=$((VULNS_FOUND + venv_vulns))
                    else
                        ok "No vulnerabilities in $venv_dir"
                    fi
                fi
            fi
        done < <(find "$root" -maxdepth "$SCAN_DEPTH" \
            -path "*/bin/activate" -o -path "*/Scripts/activate" \
            2>/dev/null | head -20)
    done

    if [[ "$found_venvs" -eq 0 ]]; then
        log "No Python virtual environments found in scan directories"
    else
        log "Scanned $found_venvs virtual environment(s)"
    fi
}

# ──────────────────────────────────────
#  SUMMARY
# ──────────────────────────────────────
print_summary() {
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        emit_json_report
        return
    fi

    header "AUDIT SUMMARY"

    _log "INFO" "Machine:          $HOSTNAME_STR ($DISTRO, $ARCH)"
    [[ "$IS_CONTAINER" == true ]] && _log "INFO" "Environment:      Container"
    [[ "$IS_CI" == true ]]        && _log "INFO" "Environment:      CI/CD"
    _log "INFO" "Date:             $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    _log "INFO" "Packages scanned: $PACKAGES_SCANNED"
    _log "INFO" "Scan errors:      $SCAN_ERRORS"
    _log "INFO" "Report saved to:  $REPORT_FILE"
    echo ""

    if [[ "$VULNS_FOUND" -gt 0 ]]; then
        vuln "TOTAL VULNERABILITIES FOUND: $VULNS_FOUND"
        echo ""
        echo -e "  ${BOLD}Recommended actions:${NC}"
        echo "    1. Run 'npm audit fix' in affected npm projects"
        echo "    2. Upgrade vulnerable pip packages"
        echo "    3. Remove any flagged malicious packages IMMEDIATELY"
        echo "    4. Rotate secrets/credentials if a malicious package was installed"
        echo "    5. Review $REPORT_FILE for details"
    else
        ok "No vulnerabilities found!"
    fi
    echo ""
}

# ──────────────────────────────────────
#  USAGE
# ──────────────────────────────────────
usage() {
    cat <<'USAGE'
Supply Chain Breach Scanner v2.0.0

Audits installed npm and PyPI packages against known supply chain
breaches, typosquats, and vulnerability databases (OSV.dev).

USAGE:
  ./supply_chain_audit.sh [OPTIONS]

OPTIONS:
  -d, --dir DIR          Directory to scan (repeatable). Default: auto-detect.
  -f, --format FORMAT    Output format: text (default) or json.
  --depth N              Max directory search depth (default: 5).
  --npm-only             Only scan npm packages.
  --pypi-only            Only scan PyPI packages.
  --offline              Skip OSV.dev API queries (malicious-list check only).
  --max-projects N       Max npm projects to audit (default: 50).
  -q, --quiet            Only print vulnerabilities and errors.
  -v, --verbose          Enable debug output.
  --no-color             Disable colored output.
  --report-dir DIR       Directory for report files (default: ~/.supply_chain_audit).
  -h, --help             Show this help message.
  --version              Show version.

EXAMPLES:
  # Full scan on a developer machine
  ./supply_chain_audit.sh

  # Scan specific project directories
  ./supply_chain_audit.sh -d /opt/myapp -d /srv/api

  # CI/CD pipeline (JSON output, non-zero exit on vulns)
  ./supply_chain_audit.sh --format json --quiet

  # Air-gapped server (no internet)
  ./supply_chain_audit.sh --offline

  # Quick npm-only scan of a deployment
  ./supply_chain_audit.sh --npm-only -d /opt/app
USAGE
    exit 0
}

# ──────────────────────────────────────
#  PARSE ARGS
# ──────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--dir)       SCAN_DIRS+=("$2"); shift 2 ;;
            -f|--format)    OUTPUT_FORMAT="$2"; shift 2 ;;
            --depth)        SCAN_DEPTH="$2"; shift 2 ;;
            --npm-only)     SCAN_PYPI=false; shift ;;
            --pypi-only)    SCAN_NPM=false; shift ;;
            --offline)      SKIP_OSV=true; shift ;;
            --max-projects) MAX_PROJECTS="$2"; shift 2 ;;
            -q|--quiet)     QUIET=true; shift ;;
            -v|--verbose)   VERBOSE=true; shift ;;
            --no-color)     NO_COLOR=1; shift ;;
            --report-dir)   REPORT_DIR="$2"; shift 2 ;;
            -h|--help)      usage ;;
            --version)      echo "supply_chain_audit v${VERSION}"; exit 0 ;;
            *)              echo "Unknown option: $1" >&2; usage ;;
        esac
    done
}

# ──────────────────────────────────────
#  MAIN
# ──────────────────────────────────────
main() {
    parse_args "$@"
    detect_platform
    setup_colors

    if ! find_python; then
        echo "ERROR: Python 3 is required but not found." >&2
        echo "Install it with your package manager (apt, yum, brew, etc.)" >&2
        exit 2
    fi

    if ! command -v curl &>/dev/null; then
        echo "ERROR: curl is required but not found." >&2
        exit 2
    fi

    find_pip || true
    init_report

    if [[ "$OUTPUT_FORMAT" != "json" ]]; then
        echo -e "${BOLD}"
        echo "╔════════════════════════════════════════════════╗"
        echo "║   Supply Chain Breach Scanner v${VERSION}          ║"
        echo "║   npm + PyPI vulnerability auditor             ║"
        echo "╠════════════════════════════════════════════════╣"
        echo "║   Host: ${HOSTNAME_STR:0:39}"
        echo "║   OS:   ${DISTRO:0:39}"
        echo "║   Arch: ${ARCH}"
        [[ "$IS_CONTAINER" == true ]] && echo "║   Env:  Container"
        [[ "$IS_CI" == true ]]        && echo "║   Env:  CI/CD"
        echo "╚════════════════════════════════════════════════╝"
        echo -e "${NC}"
    fi

    check_network || true

    check_known_malicious

    if [[ "$SCAN_NPM" == true ]]; then
        audit_npm_global
        audit_npm_projects
    fi

    if [[ "$SCAN_PYPI" == true ]]; then
        if [[ -n "$PIP_CMD" ]]; then
            audit_pip_tool || audit_pypi_osv
            scan_virtualenvs
        else
            warn "No pip found — skipping PyPI scans"
        fi
    fi

    print_summary

    if [[ "$VULNS_FOUND" -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
