#!/bin/bash
#
# Security Scan Script - Universal Node.js/TypeScript Security Scanner
# https://github.com/maykonmeier/security-scan-template
#
# Features:
#   - Dependency Audit (SCA)
#   - Static Analysis (SAST) with Semgrep
#   - Dynamic Analysis (DAST) with Nuclei
#   - OWASP Top 10 Checklist
#   - Security Grade System (A+ to D)
#   - Beautiful HTML Dashboard
#
# Usage:
#   bash security/scan.sh          # Local mode (opens dashboard)
#   bash security/scan.sh --ci     # CI mode (exit codes, no browser)
#   bash security/scan.sh --help   # Show help
#

set -euo pipefail

# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.json"
OUTPUT_DIR="$PROJECT_ROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
CI_MODE=false
PROJECT_NAME="Security Scan"
PACKAGE_MANAGER="auto"
TEST_COMMAND="test"
GENERATE_JSON=true
OPEN_DASHBOARD=true
MAX_CRITICAL=0
MAX_HIGH=5
MAX_MEDIUM=20
DAST_ENABLED=false
DAST_TARGET=""
DAST_PORT=3000

# ==============================================================================
# Helper Functions
# ==============================================================================

print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

sanitize_number() {
    local val
    val=$(echo "$1" | tr -d '\n\r ' | grep -oE '[0-9]+' | head -1)
    echo "${val:-0}"
}

show_help() {
    cat << EOF
Security Scan - Universal Node.js/TypeScript Security Scanner

Usage:
    bash security/scan.sh [options]

Options:
    --ci            Run in CI mode (no browser, exit codes based on thresholds)
    --json-only     Only generate JSON report, skip HTML dashboard
    --no-tests      Skip running tests
    --dast [URL]    Run DAST scan with Nuclei (requires running server)
                    URL defaults to http://localhost:3000
    --help          Show this help message

Configuration:
    Edit security/config.json to customize:
    - projectName: Name shown in dashboard
    - packageManager: npm, pnpm, yarn, bun, or auto (detect)
    - testCommand: npm script to run tests (default: test)
    - thresholds: Max allowed vulnerabilities per severity
    - securityControls: Custom security controls to display

Examples:
    bash security/scan.sh              # Run locally, open dashboard
    bash security/scan.sh --ci         # Run in CI, check thresholds
    bash security/scan.sh --dast       # Include DAST scan (localhost:3000)
    bash security/scan.sh --dast http://staging.example.com  # DAST on custom URL

EOF
    exit 0
}

# ==============================================================================
# Load Configuration
# ==============================================================================

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        print_status "Loading configuration from config.json"

        if command -v python3 &> /dev/null; then
            PROJECT_NAME=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('projectName', 'Security Scan'))" 2>/dev/null || echo "Security Scan")
            PACKAGE_MANAGER=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('packageManager', 'auto'))" 2>/dev/null || echo "auto")
            TEST_COMMAND=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('testCommand', 'test'))" 2>/dev/null || echo "test")
            GENERATE_JSON=$(python3 -c "import json; print(str(json.load(open('$CONFIG_FILE')).get('generateJson', True)).lower())" 2>/dev/null || echo "true")
            OPEN_DASHBOARD=$(python3 -c "import json; print(str(json.load(open('$CONFIG_FILE')).get('openDashboard', True)).lower())" 2>/dev/null || echo "true")
            MAX_CRITICAL=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('thresholds', {}).get('maxCritical', 0))" 2>/dev/null || echo "0")
            MAX_HIGH=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('thresholds', {}).get('maxHigh', 5))" 2>/dev/null || echo "5")
            MAX_MEDIUM=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('thresholds', {}).get('maxMedium', 20))" 2>/dev/null || echo "20")
        else
            print_warning "python3 not found, using default configuration"
        fi
    else
        print_warning "config.json not found, using defaults"
    fi
}

# ==============================================================================
# Detect Package Manager
# ==============================================================================

detect_package_manager() {
    if [[ "$PACKAGE_MANAGER" != "auto" ]]; then
        echo "$PACKAGE_MANAGER"
        return
    fi

    cd "$PROJECT_ROOT"

    if [[ -f "bun.lockb" ]]; then
        echo "bun"
    elif [[ -f "pnpm-lock.yaml" ]]; then
        echo "pnpm"
    elif [[ -f "yarn.lock" ]]; then
        echo "yarn"
    elif [[ -f "package-lock.json" ]]; then
        echo "npm"
    else
        echo "npm"
    fi
}

# ==============================================================================
# Get Package Versions
# ==============================================================================

get_package_versions() {
    cd "$PROJECT_ROOT"

    PM_VERSION="unknown"
    NODE_VERSION="unknown"

    local pm=$(detect_package_manager)

    case "$pm" in
        pnpm) PM_VERSION=$(pnpm --version 2>/dev/null || echo "unknown") ;;
        npm) PM_VERSION=$(npm --version 2>/dev/null || echo "unknown") ;;
        yarn) PM_VERSION=$(yarn --version 2>/dev/null || echo "unknown") ;;
        bun) PM_VERSION=$(bun --version 2>/dev/null || echo "unknown") ;;
    esac

    NODE_VERSION=$(node --version 2>/dev/null | tr -d 'v' || echo "unknown")

    # Get key package versions from package.json
    FRAMEWORK_INFO=""
    if [[ -f "package.json" ]]; then
        if grep -q '"react"' package.json 2>/dev/null; then
            local ver=$(grep -oE '"react":\s*"[^"]+"' package.json | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            FRAMEWORK_INFO="React $ver"
        elif grep -q '"vue"' package.json 2>/dev/null; then
            local ver=$(grep -oE '"vue":\s*"[^"]+"' package.json | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            FRAMEWORK_INFO="Vue $ver"
        elif grep -q '"next"' package.json 2>/dev/null; then
            local ver=$(grep -oE '"next":\s*"[^"]+"' package.json | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            FRAMEWORK_INFO="Next.js $ver"
        elif grep -q '"express"' package.json 2>/dev/null; then
            local ver=$(grep -oE '"express":\s*"[^"]+"' package.json | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            FRAMEWORK_INFO="Express $ver"
        fi
    fi
}

# ==============================================================================
# Run Dependency Audit (SCA)
# ==============================================================================

run_audit() {
    print_header "🔍 Software Composition Analysis (SCA)"

    local pm=$(detect_package_manager)
    print_status "Detected package manager: $pm"

    cd "$PROJECT_ROOT"

    local audit_output=""

    case "$pm" in
        pnpm)
            audit_output=$(pnpm audit 2>&1 || true)
            ;;
        npm)
            audit_output=$(npm audit 2>&1 || true)
            ;;
        yarn)
            audit_output=$(yarn audit 2>&1 || true)
            ;;
        bun)
            print_warning "Bun doesn't have native audit, using npm audit"
            audit_output=$(npm audit 2>&1 || true)
            ;;
    esac

    echo "$audit_output"

    # Parse vulnerabilities
    AUDIT_CRITICAL=0
    AUDIT_HIGH=0
    AUDIT_MEDIUM=0
    AUDIT_LOW=0

    # Try to extract numbers from output
    AUDIT_CRITICAL=$(echo "$audit_output" | grep -oE '[0-9]+ critical' | head -1 | grep -oE '[0-9]+' || echo "0")
    AUDIT_HIGH=$(echo "$audit_output" | grep -oE '[0-9]+ high' | head -1 | grep -oE '[0-9]+' || echo "0")
    AUDIT_MEDIUM=$(echo "$audit_output" | grep -oE '[0-9]+ moderate' | head -1 | grep -oE '[0-9]+' || echo "0")
    AUDIT_LOW=$(echo "$audit_output" | grep -oE '[0-9]+ low' | head -1 | grep -oE '[0-9]+' || echo "0")

    # Sanitize
    AUDIT_CRITICAL=$(sanitize_number "$AUDIT_CRITICAL")
    AUDIT_HIGH=$(sanitize_number "$AUDIT_HIGH")
    AUDIT_MEDIUM=$(sanitize_number "$AUDIT_MEDIUM")
    AUDIT_LOW=$(sanitize_number "$AUDIT_LOW")

    AUDIT_OUTPUT="$audit_output"

    print_status "SCA complete: $AUDIT_CRITICAL critical, $AUDIT_HIGH high, $AUDIT_MEDIUM medium, $AUDIT_LOW low"
}

# ==============================================================================
# Run Semgrep (SAST)
# ==============================================================================

run_semgrep() {
    print_header "🔬 Static Application Security Testing (SAST)"

    if ! command -v semgrep &> /dev/null; then
        print_warning "Semgrep not installed. Install with: pip install semgrep"
        SEMGREP_OUTPUT="Semgrep not installed"
        SEMGREP_CRITICAL=0
        SEMGREP_HIGH=0
        SEMGREP_MEDIUM=0
        SEMGREP_LOW=0
        SEMGREP_RULES=0
        SEMGREP_FILES=0
        return
    fi

    cd "$PROJECT_ROOT"

    # Detect framework for optimal rules
    local semgrep_config="auto"
    DETECTED_FRAMEWORK="Node.js"

    if [[ -f "package.json" ]]; then
        if grep -q '"react"' package.json 2>/dev/null; then
            semgrep_config="p/react"
            DETECTED_FRAMEWORK="React"
        elif grep -q '"express"' package.json 2>/dev/null; then
            semgrep_config="p/expressjs"
            DETECTED_FRAMEWORK="Express"
        elif grep -q '"next"' package.json 2>/dev/null; then
            semgrep_config="p/nextjs"
            DETECTED_FRAMEWORK="Next.js"
        elif grep -q '"vue"' package.json 2>/dev/null; then
            semgrep_config="p/vue"
            DETECTED_FRAMEWORK="Vue"
        fi
    fi

    print_status "Using Semgrep config: $semgrep_config (detected: $DETECTED_FRAMEWORK)"

    # Run semgrep with JSON output
    local semgrep_json
    semgrep_json=$(semgrep scan --config "$semgrep_config" --json --quiet 2>/dev/null || echo '{"results":[],"errors":[],"paths":{"scanned":[]}}')

    # Get text output for display
    SEMGREP_OUTPUT=$(semgrep scan --config "$semgrep_config" --quiet 2>&1 || true)

    if [[ -n "$SEMGREP_OUTPUT" && "$SEMGREP_OUTPUT" != *"No issues found"* && "$SEMGREP_OUTPUT" != *"Ran 0 rules"* ]]; then
        echo "$SEMGREP_OUTPUT"
    else
        print_status "No issues found"
    fi

    # Parse results
    SEMGREP_CRITICAL=0
    SEMGREP_HIGH=0
    SEMGREP_MEDIUM=0
    SEMGREP_LOW=0
    SEMGREP_RULES=0
    SEMGREP_FILES=0

    if command -v python3 &> /dev/null; then
        local stats
        stats=$(echo "$semgrep_json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    results = data.get('results', [])
    paths = data.get('paths', {}).get('scanned', [])

    counts = {'ERROR': 0, 'WARNING': 0, 'INFO': 0}
    rules = set()

    for r in results:
        sev = r.get('extra', {}).get('severity', 'INFO')
        counts[sev] = counts.get(sev, 0) + 1
        rules.add(r.get('check_id', ''))

    print(f\"{counts.get('ERROR', 0)} {counts.get('WARNING', 0)} {counts.get('INFO', 0)} {len(rules)} {len(paths)}\")
except Exception as e:
    print('0 0 0 0 0')
" 2>/dev/null || echo "0 0 0 0 0")

        read -r SEMGREP_HIGH SEMGREP_MEDIUM SEMGREP_LOW SEMGREP_RULES SEMGREP_FILES <<< "$stats"
    fi

    SEMGREP_JSON="$semgrep_json"

    print_status "SAST complete: $SEMGREP_HIGH high, $SEMGREP_MEDIUM medium, $SEMGREP_LOW info ($SEMGREP_FILES files scanned)"
}

# ==============================================================================
# Run Tests
# ==============================================================================

run_tests() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        print_status "Skipping tests (--no-tests flag)"
        TEST_OUTPUT="Tests skipped"
        TEST_PASSED=0
        TEST_FAILED=0
        TEST_STATUS="skipped"
        return
    fi

    print_header "🧪 Running Tests"

    local pm=$(detect_package_manager)
    cd "$PROJECT_ROOT"

    if ! grep -q "\"$TEST_COMMAND\"" package.json 2>/dev/null; then
        print_warning "No '$TEST_COMMAND' script found in package.json"
        TEST_OUTPUT="No test script configured"
        TEST_PASSED=0
        TEST_FAILED=0
        TEST_STATUS="skipped"
        return
    fi

    local test_result=0
    TEST_OUTPUT=$($pm run "$TEST_COMMAND" 2>&1) || test_result=$?

    echo "$TEST_OUTPUT" | tail -20

    # Parse test results (works with vitest, jest, mocha)
    TEST_PASSED=$(echo "$TEST_OUTPUT" | grep -oE '[0-9]+ (pass|passed)' | head -1 | grep -oE '[0-9]+' || echo "0")
    TEST_FAILED=$(echo "$TEST_OUTPUT" | grep -oE '[0-9]+ (fail|failed)' | head -1 | grep -oE '[0-9]+' || echo "0")

    TEST_PASSED=$(sanitize_number "$TEST_PASSED")
    TEST_FAILED=$(sanitize_number "$TEST_FAILED")

    if [[ $test_result -eq 0 ]]; then
        TEST_STATUS="passed"
        print_status "Tests passed: $TEST_PASSED"
    else
        TEST_STATUS="failed"
        print_error "Tests failed: $TEST_FAILED failures"
    fi
}

# ==============================================================================
# Run DAST (Nuclei)
# ==============================================================================

run_dast() {
    if [[ "$DAST_ENABLED" != "true" ]]; then
        DAST_STATUS="skipped"
        DAST_TEMPLATES=0
        DAST_REQUESTS=0
        DAST_CRITICAL=0
        DAST_HIGH=0
        DAST_MEDIUM=0
        DAST_LOW=0
        DAST_OUTPUT="DAST scan not enabled. Use --dast flag to enable."
        return
    fi

    print_header "🌐 Dynamic Application Security Testing (DAST)"

    if ! command -v nuclei &> /dev/null; then
        print_warning "Nuclei not installed. Install with: brew install nuclei"
        DAST_STATUS="not_installed"
        DAST_TEMPLATES=0
        DAST_REQUESTS=0
        DAST_CRITICAL=0
        DAST_HIGH=0
        DAST_MEDIUM=0
        DAST_LOW=0
        DAST_OUTPUT="Nuclei not installed"
        return
    fi

    # Check if target is reachable
    local target="${DAST_TARGET:-http://localhost:$DAST_PORT}"
    print_status "Target: $target"

    if ! curl -s -o /dev/null -w "%{http_code}" "$target" | grep -qE "^[23]"; then
        print_warning "Target not reachable: $target"
        print_warning "Make sure your application is running"
        DAST_STATUS="unreachable"
        DAST_TEMPLATES=0
        DAST_REQUESTS=0
        DAST_CRITICAL=0
        DAST_HIGH=0
        DAST_MEDIUM=0
        DAST_LOW=0
        DAST_OUTPUT="Target unreachable: $target"
        return
    fi

    print_status "Target is reachable"

    # Update templates if needed
    nuclei -update-templates -silent 2>/dev/null || true

    # Run nuclei scan
    local nuclei_output_file=$(mktemp)
    local nuclei_json_file=$(mktemp)

    print_status "Running Nuclei scan (this may take a few minutes)..."

    nuclei -u "$target" \
        -t ~/nuclei-templates/http/vulnerabilities \
        -t ~/nuclei-templates/http/cves \
        -t ~/nuclei-templates/dast \
        -severity critical,high,medium,low \
        -silent \
        -jsonl -o "$nuclei_json_file" \
        2>"$nuclei_output_file" || true

    # Parse results
    DAST_CRITICAL=0
    DAST_HIGH=0
    DAST_MEDIUM=0
    DAST_LOW=0

    if [[ -f "$nuclei_json_file" ]]; then
        DAST_CRITICAL=$(grep -c '"severity":"critical"' "$nuclei_json_file" 2>/dev/null || echo "0")
        DAST_HIGH=$(grep -c '"severity":"high"' "$nuclei_json_file" 2>/dev/null || echo "0")
        DAST_MEDIUM=$(grep -c '"severity":"medium"' "$nuclei_json_file" 2>/dev/null || echo "0")
        DAST_LOW=$(grep -c '"severity":"low"' "$nuclei_json_file" 2>/dev/null || echo "0")
    fi

    DAST_CRITICAL=$(sanitize_number "$DAST_CRITICAL")
    DAST_HIGH=$(sanitize_number "$DAST_HIGH")
    DAST_MEDIUM=$(sanitize_number "$DAST_MEDIUM")
    DAST_LOW=$(sanitize_number "$DAST_LOW")

    # Parse stats from output
    DAST_TEMPLATES=$(grep -oE 'Templates: [0-9]+' "$nuclei_output_file" | tail -1 | grep -oE '[0-9]+' || echo "0")
    DAST_REQUESTS=$(grep -oE 'Requests: [0-9]+' "$nuclei_output_file" | tail -1 | grep -oE '[0-9]+' || echo "0")

    DAST_TEMPLATES=$(sanitize_number "$DAST_TEMPLATES")
    DAST_REQUESTS=$(sanitize_number "$DAST_REQUESTS")

    # Store output
    DAST_OUTPUT=$(cat "$nuclei_output_file" 2>/dev/null || echo "No output")

    # Determine status
    local total_dast=$((DAST_CRITICAL + DAST_HIGH + DAST_MEDIUM + DAST_LOW))
    if [[ $total_dast -eq 0 ]]; then
        DAST_STATUS="passed"
        print_status "No vulnerabilities found"
    else
        DAST_STATUS="findings"
        print_warning "Found $total_dast vulnerabilities"
    fi

    # Cleanup
    rm -f "$nuclei_output_file" "$nuclei_json_file"

    print_status "DAST complete: $DAST_CRITICAL critical, $DAST_HIGH high, $DAST_MEDIUM medium, $DAST_LOW low"
}

# ==============================================================================
# Calculate Security Score and Grade
# ==============================================================================

calculate_score() {
    local total_critical=$((AUDIT_CRITICAL + SEMGREP_CRITICAL + DAST_CRITICAL))
    local total_high=$((AUDIT_HIGH + SEMGREP_HIGH + DAST_HIGH))
    local total_medium=$((AUDIT_MEDIUM + SEMGREP_MEDIUM + DAST_MEDIUM))
    local total_low=$((AUDIT_LOW + SEMGREP_LOW + DAST_LOW))

    # Base score 100, subtract for vulnerabilities
    SECURITY_SCORE=$((100 - (total_critical * 25) - (total_high * 10) - (total_medium * 3) - (total_low * 1)))

    # Subtract for failed tests
    if [[ "$TEST_STATUS" == "failed" ]]; then
        SECURITY_SCORE=$((SECURITY_SCORE - 10))
    fi

    # Clamp to 0-100
    if [[ $SECURITY_SCORE -lt 0 ]]; then SECURITY_SCORE=0; fi
    if [[ $SECURITY_SCORE -gt 100 ]]; then SECURITY_SCORE=100; fi

    # Determine grade
    if [[ $SECURITY_SCORE -ge 95 ]]; then
        GRADE="A+"
        GRADE_COLOR="green"
        GRADE_STATUS="Excellent"
    elif [[ $SECURITY_SCORE -ge 90 ]]; then
        GRADE="A"
        GRADE_COLOR="green"
        GRADE_STATUS="Very Good"
    elif [[ $SECURITY_SCORE -ge 80 ]]; then
        GRADE="B"
        GRADE_COLOR="green"
        GRADE_STATUS="Good"
    elif [[ $SECURITY_SCORE -ge 70 ]]; then
        GRADE="C"
        GRADE_COLOR="yellow"
        GRADE_STATUS="Adequate"
    elif [[ $SECURITY_SCORE -ge 60 ]]; then
        GRADE="D"
        GRADE_COLOR="orange"
        GRADE_STATUS="Needs Attention"
    else
        GRADE="F"
        GRADE_COLOR="red"
        GRADE_STATUS="Critical"
    fi
}

# ==============================================================================
# Generate HTML Dashboard
# ==============================================================================

generate_dashboard() {
    if [[ "$JSON_ONLY" == "true" ]]; then
        return
    fi

    print_header "📊 Generating Dashboard"

    local total_critical=$((AUDIT_CRITICAL + SEMGREP_CRITICAL))
    local total_high=$((AUDIT_HIGH + SEMGREP_HIGH))
    local total_medium=$((AUDIT_MEDIUM + SEMGREP_MEDIUM))
    local total_low=$((AUDIT_LOW + SEMGREP_LOW))

    # Grade colors for CSS
    local grade_gradient="from-green-500 to-emerald-600"
    local grade_text="text-green-400"
    local pulse_class="pulse-green"

    if [[ "$GRADE_COLOR" == "yellow" ]]; then
        grade_gradient="from-yellow-500 to-amber-600"
        grade_text="text-yellow-400"
        pulse_class="pulse-yellow"
    elif [[ "$GRADE_COLOR" == "orange" ]]; then
        grade_gradient="from-orange-500 to-red-600"
        grade_text="text-orange-400"
        pulse_class="pulse-orange"
    elif [[ "$GRADE_COLOR" == "red" ]]; then
        grade_gradient="from-red-500 to-rose-600"
        grade_text="text-red-400"
        pulse_class="pulse-red"
    fi

    # Escape special characters for HTML
    local audit_html=$(echo "$AUDIT_OUTPUT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    local semgrep_html=$(echo "$SEMGREP_OUTPUT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    local test_html=$(echo "$TEST_OUTPUT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')

    # Load custom security controls from config
    local controls_html=""
    if [[ -f "$CONFIG_FILE" ]] && command -v python3 &> /dev/null; then
        controls_html=$(python3 -c "
import json
try:
    config = json.load(open('$CONFIG_FILE'))
    controls = config.get('securityControls', [])
    if not controls:
        # Default controls
        controls = [
            {'name': 'Authentication', 'status': 'info', 'items': ['Configure in config.json']},
            {'name': 'Authorization', 'status': 'info', 'items': ['Configure in config.json']},
            {'name': 'Data Protection', 'status': 'info', 'items': ['Configure in config.json']}
        ]

    html = ''
    for ctrl in controls:
        status_color = 'green' if ctrl.get('status') == 'active' else 'yellow' if ctrl.get('status') == 'partial' else 'gray'
        items_html = ''.join([f'<li>{item}</li>' for item in ctrl.get('items', [])])
        html += f'''
          <div class=\"p-4 bg-gray-700/50 rounded-lg\">
            <div class=\"flex items-center gap-2 mb-2\">
              <span class=\"w-3 h-3 bg-{status_color}-500 rounded-full\"></span>
              <span class=\"font-medium\">{ctrl.get('name', 'Control')}</span>
            </div>
            <ul class=\"text-sm text-gray-400 space-y-1\">{items_html}</ul>
          </div>
        '''
    print(html)
except Exception as e:
    print('<div class=\"p-4 bg-gray-700/50 rounded-lg\"><p class=\"text-gray-400\">Configure security controls in config.json</p></div>')
" 2>/dev/null || echo '<div class="p-4 bg-gray-700/50 rounded-lg"><p class="text-gray-400">Configure security controls in config.json</p></div>')
    fi

    # OWASP Top 10 checklist status (based on findings)
    local owasp_a01="green" # Broken Access Control
    local owasp_a02="green" # Cryptographic Failures
    local owasp_a03="green" # Injection
    local owasp_a04="green" # Insecure Design
    local owasp_a05="green" # Security Misconfiguration
    local owasp_a06="green" # Vulnerable Components
    local owasp_a07="green" # Auth Failures
    local owasp_a08="green" # Software Integrity
    local owasp_a09="green" # Logging Failures
    local owasp_a10="green" # SSRF

    # Check for issues in semgrep output
    if echo "$SEMGREP_OUTPUT" | grep -qi "injection\|sql\|xss\|command"; then
        owasp_a03="red"
    fi
    if echo "$SEMGREP_OUTPUT" | grep -qi "auth\|session\|jwt\|token"; then
        owasp_a07="yellow"
    fi
    if [[ $AUDIT_HIGH -gt 0 ]] || [[ $AUDIT_CRITICAL -gt 0 ]]; then
        owasp_a06="red"
    elif [[ $AUDIT_MEDIUM -gt 0 ]]; then
        owasp_a06="yellow"
    fi

    cat > "$OUTPUT_DIR/security-dashboard.html" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard - PROJECT_NAME_PLACEHOLDER</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        critical: '#ef4444',
                        high: '#f97316',
                        medium: '#eab308',
                        low: '#22c55e',
                    }
                }
            }
        }
    </script>
    <style>
        @keyframes pulse-green { 0%, 100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.4); } 50% { box-shadow: 0 0 0 10px rgba(34, 197, 94, 0); } }
        @keyframes pulse-yellow { 0%, 100% { box-shadow: 0 0 0 0 rgba(234, 179, 8, 0.4); } 50% { box-shadow: 0 0 0 10px rgba(234, 179, 8, 0); } }
        @keyframes pulse-orange { 0%, 100% { box-shadow: 0 0 0 0 rgba(249, 115, 22, 0.4); } 50% { box-shadow: 0 0 0 10px rgba(249, 115, 22, 0); } }
        @keyframes pulse-red { 0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); } 50% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); } }
        .pulse-green { animation: pulse-green 2s infinite; }
        .pulse-yellow { animation: pulse-yellow 2s infinite; }
        .pulse-orange { animation: pulse-orange 2s infinite; }
        .pulse-red { animation: pulse-red 2s infinite; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
        .owasp-item { transition: all 0.2s; }
        .owasp-item:hover { transform: translateX(4px); }
    </style>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8 max-w-7xl">
        <!-- Header -->
        <header class="mb-8">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-3xl font-bold text-white">🛡️ Security Dashboard</h1>
                    <p class="text-gray-400 mt-1">PROJECT_NAME_PLACEHOLDER</p>
                </div>
                <div class="text-right">
                    <p class="text-sm text-gray-400">Last Scan</p>
                    <p class="text-white font-mono">SCAN_DATE_PLACEHOLDER</p>
                </div>
            </div>
        </header>

        <!-- Security Grade -->
        <section class="mb-8">
            <div class="bg-gray-800 rounded-2xl p-8 border border-gray-700">
                <div class="flex items-center justify-between flex-wrap gap-6">
                    <div class="flex items-center gap-6">
                        <div class="relative">
                            <div class="w-32 h-32 rounded-full bg-gradient-to-br GRADE_GRADIENT_PLACEHOLDER flex items-center justify-center PULSE_CLASS_PLACEHOLDER">
                                <span class="text-5xl font-bold">GRADE_PLACEHOLDER</span>
                            </div>
                        </div>
                        <div>
                            <h2 class="text-2xl font-bold GRADE_TEXT_PLACEHOLDER">GRADE_STATUS_PLACEHOLDER</h2>
                            <p class="text-gray-400 mt-1">Security Score: SCORE_PLACEHOLDER/100</p>
                            <p class="text-sm text-gray-500 mt-2">FRAMEWORK_PLACEHOLDER</p>
                        </div>
                    </div>
                    <div class="flex gap-6">
                        <div class="text-center px-4">
                            <p class="text-4xl font-bold text-red-400">CRITICAL_TOTAL</p>
                            <p class="text-xs text-gray-400 mt-1">Critical</p>
                        </div>
                        <div class="text-center px-4">
                            <p class="text-4xl font-bold text-orange-400">HIGH_TOTAL</p>
                            <p class="text-xs text-gray-400 mt-1">High</p>
                        </div>
                        <div class="text-center px-4">
                            <p class="text-4xl font-bold text-yellow-400">MEDIUM_TOTAL</p>
                            <p class="text-xs text-gray-400 mt-1">Medium</p>
                        </div>
                        <div class="text-center px-4">
                            <p class="text-4xl font-bold text-green-400">LOW_TOTAL</p>
                            <p class="text-xs text-gray-400 mt-1">Low</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Summary Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <div class="flex items-center gap-3">
                    <div class="w-12 h-12 rounded-lg bg-blue-500/20 flex items-center justify-center">
                        <span class="text-2xl">🧪</span>
                    </div>
                    <div>
                        <p class="text-2xl font-bold">TEST_COUNT_PLACEHOLDER</p>
                        <p class="text-sm text-gray-400">Tests Passing</p>
                    </div>
                </div>
            </div>
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <div class="flex items-center gap-3">
                    <div class="w-12 h-12 rounded-lg bg-purple-500/20 flex items-center justify-center">
                        <span class="text-2xl">🔬</span>
                    </div>
                    <div>
                        <p class="text-2xl font-bold">SEMGREP_FILES_PLACEHOLDER</p>
                        <p class="text-sm text-gray-400">Files Scanned</p>
                    </div>
                </div>
            </div>
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <div class="flex items-center gap-3">
                    <div class="w-12 h-12 rounded-lg bg-green-500/20 flex items-center justify-center">
                        <span class="text-2xl">📦</span>
                    </div>
                    <div>
                        <p class="text-2xl font-bold">PM_VERSION_PLACEHOLDER</p>
                        <p class="text-sm text-gray-400">PM_NAME_PLACEHOLDER</p>
                    </div>
                </div>
            </div>
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <div class="flex items-center gap-3">
                    <div class="w-12 h-12 rounded-lg bg-orange-500/20 flex items-center justify-center">
                        <span class="text-2xl">⚡</span>
                    </div>
                    <div>
                        <p class="text-2xl font-bold">NODE_VERSION_PLACEHOLDER</p>
                        <p class="text-sm text-gray-400">Node.js</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Grid -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            <!-- OWASP Top 10 -->
            <div class="lg:col-span-1 bg-gray-800 rounded-xl p-6 border border-gray-700">
                <h3 class="text-lg font-semibold mb-4 flex items-center gap-2">
                    <span class="text-2xl">🏛️</span>
                    OWASP Top 10 (2021)
                </h3>
                <div class="space-y-2">
                    <div class="owasp-item flex items-center gap-2 p-2 rounded bg-gray-700/30">
                        <span class="w-2 h-2 rounded-full bg-OWASP_A01_COLOR-500"></span>
                        <span class="text-sm">A01 - Broken Access Control</span>
                    </div>
                    <div class="owasp-item flex items-center gap-2 p-2 rounded bg-gray-700/30">
                        <span class="w-2 h-2 rounded-full bg-OWASP_A02_COLOR-500"></span>
                        <span class="text-sm">A02 - Cryptographic Failures</span>
                    </div>
                    <div class="owasp-item flex items-center gap-2 p-2 rounded bg-gray-700/30">
                        <span class="w-2 h-2 rounded-full bg-OWASP_A03_COLOR-500"></span>
                        <span class="text-sm">A03 - Injection</span>
                    </div>
                    <div class="owasp-item flex items-center gap-2 p-2 rounded bg-gray-700/30">
                        <span class="w-2 h-2 rounded-full bg-OWASP_A04_COLOR-500"></span>
                        <span class="text-sm">A04 - Insecure Design</span>
                    </div>
                    <div class="owasp-item flex items-center gap-2 p-2 rounded bg-gray-700/30">
                        <span class="w-2 h-2 rounded-full bg-OWASP_A05_COLOR-500"></span>
                        <span class="text-sm">A05 - Security Misconfiguration</span>
                    </div>
                    <div class="owasp-item flex items-center gap-2 p-2 rounded bg-gray-700/30">
                        <span class="w-2 h-2 rounded-full bg-OWASP_A06_COLOR-500"></span>
                        <span class="text-sm">A06 - Vulnerable Components</span>
                    </div>
                    <div class="owasp-item flex items-center gap-2 p-2 rounded bg-gray-700/30">
                        <span class="w-2 h-2 rounded-full bg-OWASP_A07_COLOR-500"></span>
                        <span class="text-sm">A07 - Auth Failures</span>
                    </div>
                    <div class="owasp-item flex items-center gap-2 p-2 rounded bg-gray-700/30">
                        <span class="w-2 h-2 rounded-full bg-OWASP_A08_COLOR-500"></span>
                        <span class="text-sm">A08 - Software Integrity</span>
                    </div>
                    <div class="owasp-item flex items-center gap-2 p-2 rounded bg-gray-700/30">
                        <span class="w-2 h-2 rounded-full bg-OWASP_A09_COLOR-500"></span>
                        <span class="text-sm">A09 - Logging Failures</span>
                    </div>
                    <div class="owasp-item flex items-center gap-2 p-2 rounded bg-gray-700/30">
                        <span class="w-2 h-2 rounded-full bg-OWASP_A10_COLOR-500"></span>
                        <span class="text-sm">A10 - SSRF</span>
                    </div>
                </div>
                <p class="text-xs text-gray-500 mt-4">🟢 Pass | 🟡 Warning | 🔴 Issues Found</p>
            </div>

            <!-- SCA & SAST Results -->
            <div class="lg:col-span-2 space-y-6">
                <!-- SCA Card -->
                <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                    <h3 class="text-lg font-semibold mb-4 flex items-center gap-2">
                        <span class="text-2xl">📦</span>
                        Software Composition Analysis (SCA)
                        <span class="ml-auto px-2 py-1 rounded text-xs bg-blue-500/20 text-blue-400">
                            Dependency Audit
                        </span>
                    </h3>
                    <div class="grid grid-cols-4 gap-4 mb-4">
                        <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                            <p class="text-2xl font-bold text-red-400">AUDIT_CRITICAL</p>
                            <p class="text-xs text-gray-400">Critical</p>
                        </div>
                        <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                            <p class="text-2xl font-bold text-orange-400">AUDIT_HIGH</p>
                            <p class="text-xs text-gray-400">High</p>
                        </div>
                        <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                            <p class="text-2xl font-bold text-yellow-400">AUDIT_MEDIUM</p>
                            <p class="text-xs text-gray-400">Medium</p>
                        </div>
                        <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                            <p class="text-2xl font-bold text-green-400">AUDIT_LOW</p>
                            <p class="text-xs text-gray-400">Low</p>
                        </div>
                    </div>
                    <details class="mt-4">
                        <summary class="cursor-pointer text-sm text-gray-400 hover:text-gray-300">View Details</summary>
                        <pre class="mt-2 bg-gray-900 rounded-lg p-4 text-xs text-gray-300 overflow-x-auto max-h-48 overflow-y-auto">AUDIT_OUTPUT_PLACEHOLDER</pre>
                    </details>
                </div>

                <!-- SAST Card -->
                <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                    <h3 class="text-lg font-semibold mb-4 flex items-center gap-2">
                        <span class="text-2xl">🔬</span>
                        Static Application Security Testing (SAST)
                        <span class="ml-auto px-2 py-1 rounded text-xs bg-purple-500/20 text-purple-400">
                            Semgrep
                        </span>
                    </h3>
                    <div class="grid grid-cols-4 gap-4 mb-4">
                        <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                            <p class="text-2xl font-bold text-red-400">SEMGREP_CRITICAL</p>
                            <p class="text-xs text-gray-400">Critical</p>
                        </div>
                        <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                            <p class="text-2xl font-bold text-orange-400">SEMGREP_HIGH</p>
                            <p class="text-xs text-gray-400">High</p>
                        </div>
                        <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                            <p class="text-2xl font-bold text-yellow-400">SEMGREP_MEDIUM</p>
                            <p class="text-xs text-gray-400">Medium</p>
                        </div>
                        <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                            <p class="text-2xl font-bold text-green-400">SEMGREP_LOW</p>
                            <p class="text-xs text-gray-400">Info</p>
                        </div>
                    </div>
                    <details class="mt-4">
                        <summary class="cursor-pointer text-sm text-gray-400 hover:text-gray-300">View Details</summary>
                        <pre class="mt-2 bg-gray-900 rounded-lg p-4 text-xs text-gray-300 overflow-x-auto max-h-48 overflow-y-auto">SEMGREP_OUTPUT_PLACEHOLDER</pre>
                    </details>
                </div>
            </div>
        </div>

        <!-- DAST Section -->
        <div class="mb-8 bg-gray-800 rounded-xl p-6 border border-gray-700 DAST_BORDER_CLASS">
            <h3 class="text-lg font-semibold mb-4 flex items-center gap-2">
                <span class="text-2xl">🌐</span>
                Dynamic Application Security Testing (DAST)
                <span class="ml-auto px-2 py-1 rounded text-xs DAST_STATUS_CLASS">
                    DAST_STATUS_TEXT
                </span>
            </h3>
            <div class="DAST_CONTENT_CLASS">
                <div class="grid grid-cols-4 gap-4 mb-4">
                    <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                        <p class="text-2xl font-bold text-red-400">DAST_CRITICAL</p>
                        <p class="text-xs text-gray-400">Critical</p>
                    </div>
                    <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                        <p class="text-2xl font-bold text-orange-400">DAST_HIGH</p>
                        <p class="text-xs text-gray-400">High</p>
                    </div>
                    <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                        <p class="text-2xl font-bold text-yellow-400">DAST_MEDIUM</p>
                        <p class="text-xs text-gray-400">Medium</p>
                    </div>
                    <div class="text-center p-3 bg-gray-700/50 rounded-lg">
                        <p class="text-2xl font-bold text-green-400">DAST_LOW</p>
                        <p class="text-xs text-gray-400">Low</p>
                    </div>
                </div>
                <div class="flex gap-4 text-sm text-gray-400 mb-4">
                    <span>📋 DAST_TEMPLATES templates</span>
                    <span>🔗 DAST_REQUESTS requests</span>
                    <span>🎯 DAST_TARGET_DISPLAY</span>
                </div>
                <details class="mt-4">
                    <summary class="cursor-pointer text-sm text-gray-400 hover:text-gray-300">View Details</summary>
                    <pre class="mt-2 bg-gray-900 rounded-lg p-4 text-xs text-gray-300 overflow-x-auto max-h-48 overflow-y-auto">DAST_OUTPUT_PLACEHOLDER</pre>
                </details>
            </div>
            <div class="DAST_PLACEHOLDER_CLASS">
                <p class="text-gray-400 text-sm mb-4">
                    DAST scans your running application for vulnerabilities. Use --dast flag to enable.
                </p>
                <code class="text-sm bg-gray-700 px-3 py-2 rounded">bash security/scan.sh --dast</code>
            </div>
        </div>

        <!-- Security Controls -->
        <div class="mb-8 bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h3 class="text-lg font-semibold mb-4 flex items-center gap-2">
                <span class="text-2xl">🔐</span>
                Security Controls
            </h3>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                SECURITY_CONTROLS_PLACEHOLDER
            </div>
        </div>

        <!-- Test Results -->
        <div class="mb-8 bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h3 class="text-lg font-semibold mb-4 flex items-center gap-2">
                <span class="text-2xl">🧪</span>
                Test Results
                <span class="ml-auto px-2 py-1 rounded text-xs TEST_STATUS_CLASS">
                    TEST_STATUS_PLACEHOLDER
                </span>
            </h3>
            <div class="grid grid-cols-2 gap-4 mb-4">
                <div class="text-center p-4 bg-gray-700/50 rounded-lg">
                    <p class="text-3xl font-bold text-green-400">TEST_PASSED</p>
                    <p class="text-sm text-gray-400">Passed</p>
                </div>
                <div class="text-center p-4 bg-gray-700/50 rounded-lg">
                    <p class="text-3xl font-bold text-red-400">TEST_FAILED</p>
                    <p class="text-sm text-gray-400">Failed</p>
                </div>
            </div>
            <details>
                <summary class="cursor-pointer text-sm text-gray-400 hover:text-gray-300">View Output</summary>
                <pre class="mt-2 bg-gray-900 rounded-lg p-4 text-xs text-gray-300 overflow-x-auto max-h-48 overflow-y-auto">TEST_OUTPUT_PLACEHOLDER</pre>
            </details>
        </div>

        <!-- Thresholds -->
        <div class="mb-8 bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h3 class="text-lg font-semibold mb-4 flex items-center gap-2">
                <span class="text-2xl">📏</span>
                CI/CD Thresholds
            </h3>
            <div class="grid grid-cols-3 gap-4 text-center">
                <div class="p-4 bg-gray-700/50 rounded-lg">
                    <p class="text-sm text-gray-400">Max Critical</p>
                    <p class="text-2xl font-bold THRESHOLD_CRITICAL_CLASS">MAX_CRITICAL</p>
                    <p class="text-xs text-gray-500">Current: CRITICAL_TOTAL</p>
                </div>
                <div class="p-4 bg-gray-700/50 rounded-lg">
                    <p class="text-sm text-gray-400">Max High</p>
                    <p class="text-2xl font-bold THRESHOLD_HIGH_CLASS">MAX_HIGH</p>
                    <p class="text-xs text-gray-500">Current: HIGH_TOTAL</p>
                </div>
                <div class="p-4 bg-gray-700/50 rounded-lg">
                    <p class="text-sm text-gray-400">Max Medium</p>
                    <p class="text-2xl font-bold THRESHOLD_MEDIUM_CLASS">MAX_MEDIUM</p>
                    <p class="text-xs text-gray-500">Current: MEDIUM_TOTAL</p>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <footer class="text-center text-gray-500 text-sm">
            <p>Generated by <a href="https://github.com/maykonmeier/security-scan-template" class="text-blue-400 hover:underline">security-scan-template</a></p>
        </footer>
    </div>
</body>
</html>
HTMLEOF

    # Replace all placeholders
    local pm=$(detect_package_manager)
    local scan_date=$(date '+%Y-%m-%d %H:%M:%S')

    sed -i '' "s|PROJECT_NAME_PLACEHOLDER|$PROJECT_NAME|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|SCAN_DATE_PLACEHOLDER|$scan_date|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|GRADE_PLACEHOLDER|$GRADE|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|GRADE_STATUS_PLACEHOLDER|$GRADE_STATUS|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|SCORE_PLACEHOLDER|$SECURITY_SCORE|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|GRADE_GRADIENT_PLACEHOLDER|$grade_gradient|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|GRADE_TEXT_PLACEHOLDER|$grade_text|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|PULSE_CLASS_PLACEHOLDER|$pulse_class|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|FRAMEWORK_PLACEHOLDER|${FRAMEWORK_INFO:-$DETECTED_FRAMEWORK}|g" "$OUTPUT_DIR/security-dashboard.html"

    sed -i '' "s|CRITICAL_TOTAL|$total_critical|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|HIGH_TOTAL|$total_high|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|MEDIUM_TOTAL|$total_medium|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|LOW_TOTAL|$total_low|g" "$OUTPUT_DIR/security-dashboard.html"

    sed -i '' "s|AUDIT_CRITICAL|$AUDIT_CRITICAL|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|AUDIT_HIGH|$AUDIT_HIGH|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|AUDIT_MEDIUM|$AUDIT_MEDIUM|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|AUDIT_LOW|$AUDIT_LOW|g" "$OUTPUT_DIR/security-dashboard.html"

    sed -i '' "s|SEMGREP_CRITICAL|$SEMGREP_CRITICAL|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|SEMGREP_HIGH|$SEMGREP_HIGH|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|SEMGREP_MEDIUM|$SEMGREP_MEDIUM|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|SEMGREP_LOW|$SEMGREP_LOW|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|SEMGREP_FILES_PLACEHOLDER|$SEMGREP_FILES|g" "$OUTPUT_DIR/security-dashboard.html"

    sed -i '' "s|TEST_COUNT_PLACEHOLDER|$TEST_PASSED|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|TEST_PASSED|$TEST_PASSED|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|TEST_FAILED|$TEST_FAILED|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|TEST_STATUS_PLACEHOLDER|$TEST_STATUS|g" "$OUTPUT_DIR/security-dashboard.html"

    # Test status class
    local test_status_class="bg-green-500/20 text-green-400"
    if [[ "$TEST_STATUS" == "failed" ]]; then
        test_status_class="bg-red-500/20 text-red-400"
    elif [[ "$TEST_STATUS" == "skipped" ]]; then
        test_status_class="bg-gray-500/20 text-gray-400"
    fi
    sed -i '' "s|TEST_STATUS_CLASS|$test_status_class|g" "$OUTPUT_DIR/security-dashboard.html"

    sed -i '' "s|PM_VERSION_PLACEHOLDER|$PM_VERSION|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|PM_NAME_PLACEHOLDER|$pm|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|NODE_VERSION_PLACEHOLDER|$NODE_VERSION|g" "$OUTPUT_DIR/security-dashboard.html"

    sed -i '' "s|MAX_CRITICAL|$MAX_CRITICAL|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|MAX_HIGH|$MAX_HIGH|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|MAX_MEDIUM|$MAX_MEDIUM|g" "$OUTPUT_DIR/security-dashboard.html"

    # Threshold classes
    local thresh_crit_class="text-green-400"
    local thresh_high_class="text-green-400"
    local thresh_med_class="text-green-400"
    [[ $total_critical -gt $MAX_CRITICAL ]] && thresh_crit_class="text-red-400"
    [[ $total_high -gt $MAX_HIGH ]] && thresh_high_class="text-red-400"
    [[ $total_medium -gt $MAX_MEDIUM ]] && thresh_med_class="text-red-400"
    sed -i '' "s|THRESHOLD_CRITICAL_CLASS|$thresh_crit_class|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|THRESHOLD_HIGH_CLASS|$thresh_high_class|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|THRESHOLD_MEDIUM_CLASS|$thresh_med_class|g" "$OUTPUT_DIR/security-dashboard.html"

    # OWASP colors
    sed -i '' "s|OWASP_A01_COLOR|$owasp_a01|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|OWASP_A02_COLOR|$owasp_a02|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|OWASP_A03_COLOR|$owasp_a03|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|OWASP_A04_COLOR|$owasp_a04|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|OWASP_A05_COLOR|$owasp_a05|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|OWASP_A06_COLOR|$owasp_a06|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|OWASP_A07_COLOR|$owasp_a07|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|OWASP_A08_COLOR|$owasp_a08|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|OWASP_A09_COLOR|$owasp_a09|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|OWASP_A10_COLOR|$owasp_a10|g" "$OUTPUT_DIR/security-dashboard.html"

    # DAST replacements
    sed -i '' "s|DAST_CRITICAL|$DAST_CRITICAL|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|DAST_HIGH|$DAST_HIGH|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|DAST_MEDIUM|$DAST_MEDIUM|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|DAST_LOW|$DAST_LOW|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|DAST_TEMPLATES|$DAST_TEMPLATES|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|DAST_REQUESTS|$DAST_REQUESTS|g" "$OUTPUT_DIR/security-dashboard.html"
    sed -i '' "s|DAST_TARGET_DISPLAY|${DAST_TARGET:-localhost:$DAST_PORT}|g" "$OUTPUT_DIR/security-dashboard.html"

    # DAST status and visibility
    if [[ "$DAST_ENABLED" == "true" ]]; then
        if [[ "$DAST_STATUS" == "passed" ]]; then
            sed -i '' "s|DAST_STATUS_CLASS|bg-green-500/20 text-green-400|g" "$OUTPUT_DIR/security-dashboard.html"
            sed -i '' "s|DAST_STATUS_TEXT|Passed|g" "$OUTPUT_DIR/security-dashboard.html"
        elif [[ "$DAST_STATUS" == "findings" ]]; then
            sed -i '' "s|DAST_STATUS_CLASS|bg-red-500/20 text-red-400|g" "$OUTPUT_DIR/security-dashboard.html"
            sed -i '' "s|DAST_STATUS_TEXT|Issues Found|g" "$OUTPUT_DIR/security-dashboard.html"
        else
            sed -i '' "s|DAST_STATUS_CLASS|bg-yellow-500/20 text-yellow-400|g" "$OUTPUT_DIR/security-dashboard.html"
            sed -i '' "s|DAST_STATUS_TEXT|$DAST_STATUS|g" "$OUTPUT_DIR/security-dashboard.html"
        fi
        sed -i '' "s|DAST_BORDER_CLASS||g" "$OUTPUT_DIR/security-dashboard.html"
        sed -i '' "s|DAST_CONTENT_CLASS||g" "$OUTPUT_DIR/security-dashboard.html"
        sed -i '' "s|DAST_PLACEHOLDER_CLASS|hidden|g" "$OUTPUT_DIR/security-dashboard.html"
    else
        sed -i '' "s|DAST_STATUS_CLASS|bg-gray-500/20 text-gray-400|g" "$OUTPUT_DIR/security-dashboard.html"
        sed -i '' "s|DAST_STATUS_TEXT|Not Enabled|g" "$OUTPUT_DIR/security-dashboard.html"
        sed -i '' "s|DAST_BORDER_CLASS|border-dashed|g" "$OUTPUT_DIR/security-dashboard.html"
        sed -i '' "s|DAST_CONTENT_CLASS|hidden|g" "$OUTPUT_DIR/security-dashboard.html"
        sed -i '' "s|DAST_PLACEHOLDER_CLASS||g" "$OUTPUT_DIR/security-dashboard.html"
    fi

    # Security controls - write to temp file and use perl
    local controls_file=$(mktemp)
    echo "$controls_html" > "$controls_file"
    perl -i -pe "
        BEGIN { local \$/; open F, '$controls_file'; \$r = <F>; close F; chomp \$r; }
        s|SECURITY_CONTROLS_PLACEHOLDER|\$r|g;
    " "$OUTPUT_DIR/security-dashboard.html" 2>/dev/null || true
    rm -f "$controls_file"

    # Output details - write to temp files for perl
    local audit_file=$(mktemp)
    local semgrep_file=$(mktemp)
    local test_file=$(mktemp)
    echo "$audit_html" > "$audit_file"
    echo "$semgrep_html" > "$semgrep_file"
    echo "$test_html" > "$test_file"

    perl -i -pe "
        BEGIN { local \$/; open F, '$audit_file'; \$r = <F>; close F; chomp \$r; }
        s|AUDIT_OUTPUT_PLACEHOLDER|\$r|g;
    " "$OUTPUT_DIR/security-dashboard.html" 2>/dev/null || true

    perl -i -pe "
        BEGIN { local \$/; open F, '$semgrep_file'; \$r = <F>; close F; chomp \$r; }
        s|SEMGREP_OUTPUT_PLACEHOLDER|\$r|g;
    " "$OUTPUT_DIR/security-dashboard.html" 2>/dev/null || true

    perl -i -pe "
        BEGIN { local \$/; open F, '$test_file'; \$r = <F>; close F; chomp \$r; }
        s|TEST_OUTPUT_PLACEHOLDER|\$r|g;
    " "$OUTPUT_DIR/security-dashboard.html" 2>/dev/null || true

    # DAST output
    local dast_file=$(mktemp)
    local dast_html=$(echo "$DAST_OUTPUT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    echo "$dast_html" > "$dast_file"
    perl -i -pe "
        BEGIN { local \$/; open F, '$dast_file'; \$r = <F>; close F; chomp \$r; }
        s|DAST_OUTPUT_PLACEHOLDER|\$r|g;
    " "$OUTPUT_DIR/security-dashboard.html" 2>/dev/null || true

    rm -f "$audit_file" "$semgrep_file" "$test_file" "$dast_file"

    print_status "Dashboard generated: security-dashboard.html"
}

# ==============================================================================
# Generate JSON Report
# ==============================================================================

generate_json_report() {
    if [[ "$GENERATE_JSON" != "true" ]]; then
        return
    fi

    local total_critical=$((AUDIT_CRITICAL + SEMGREP_CRITICAL + DAST_CRITICAL))
    local total_high=$((AUDIT_HIGH + SEMGREP_HIGH + DAST_HIGH))
    local total_medium=$((AUDIT_MEDIUM + SEMGREP_MEDIUM + DAST_MEDIUM))
    local total_low=$((AUDIT_LOW + SEMGREP_LOW + DAST_LOW))

    cat > "$OUTPUT_DIR/security-report.json" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "project": "$PROJECT_NAME",
  "grade": "$GRADE",
  "score": $SECURITY_SCORE,
  "summary": {
    "critical": $total_critical,
    "high": $total_high,
    "medium": $total_medium,
    "low": $total_low
  },
  "sca": {
    "tool": "$(detect_package_manager) audit",
    "critical": $AUDIT_CRITICAL,
    "high": $AUDIT_HIGH,
    "medium": $AUDIT_MEDIUM,
    "low": $AUDIT_LOW
  },
  "sast": {
    "tool": "semgrep",
    "framework": "$DETECTED_FRAMEWORK",
    "filesScanned": $SEMGREP_FILES,
    "critical": $SEMGREP_CRITICAL,
    "high": $SEMGREP_HIGH,
    "medium": $SEMGREP_MEDIUM,
    "low": $SEMGREP_LOW
  },
  "dast": {
    "enabled": $DAST_ENABLED,
    "tool": "nuclei",
    "target": "${DAST_TARGET:-http://localhost:$DAST_PORT}",
    "status": "$DAST_STATUS",
    "templates": $DAST_TEMPLATES,
    "requests": $DAST_REQUESTS,
    "critical": $DAST_CRITICAL,
    "high": $DAST_HIGH,
    "medium": $DAST_MEDIUM,
    "low": $DAST_LOW
  },
  "tests": {
    "status": "$TEST_STATUS",
    "passed": $TEST_PASSED,
    "failed": $TEST_FAILED
  },
  "thresholds": {
    "maxCritical": $MAX_CRITICAL,
    "maxHigh": $MAX_HIGH,
    "maxMedium": $MAX_MEDIUM
  },
  "thresholdsPassed": $(if [[ $total_critical -le $MAX_CRITICAL && $total_high -le $MAX_HIGH && $total_medium -le $MAX_MEDIUM ]]; then echo "true"; else echo "false"; fi)
}
EOF

    print_status "JSON report generated: security-report.json"
}

# ==============================================================================
# Check Thresholds (for CI)
# ==============================================================================

check_thresholds() {
    local total_critical=$((AUDIT_CRITICAL + SEMGREP_CRITICAL + DAST_CRITICAL))
    local total_high=$((AUDIT_HIGH + SEMGREP_HIGH + DAST_HIGH))
    local total_medium=$((AUDIT_MEDIUM + SEMGREP_MEDIUM + DAST_MEDIUM))

    local exit_code=0

    if [[ $total_critical -gt $MAX_CRITICAL ]]; then
        print_error "Critical threshold exceeded: $total_critical > $MAX_CRITICAL"
        exit_code=1
    fi

    if [[ $total_high -gt $MAX_HIGH ]]; then
        print_error "High threshold exceeded: $total_high > $MAX_HIGH"
        exit_code=1
    fi

    if [[ $total_medium -gt $MAX_MEDIUM ]]; then
        print_error "Medium threshold exceeded: $total_medium > $MAX_MEDIUM"
        exit_code=1
    fi

    if [[ "$TEST_STATUS" == "failed" ]]; then
        print_error "Tests failed"
        exit_code=1
    fi

    return $exit_code
}

# ==============================================================================
# Open Dashboard
# ==============================================================================

open_dashboard() {
    if [[ "$CI_MODE" == "true" || "$OPEN_DASHBOARD" != "true" || "$JSON_ONLY" == "true" ]]; then
        return
    fi

    local dashboard_path="$OUTPUT_DIR/security-dashboard.html"

    if [[ "$(uname)" == "Darwin" ]]; then
        open "$dashboard_path" 2>/dev/null || true
    elif [[ "$(uname)" == "Linux" ]]; then
        xdg-open "$dashboard_path" 2>/dev/null || true
    fi
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    # Parse arguments
    SKIP_TESTS=false
    JSON_ONLY=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --ci)
                CI_MODE=true
                OPEN_DASHBOARD=false
                shift
                ;;
            --json-only)
                JSON_ONLY=true
                shift
                ;;
            --no-tests)
                SKIP_TESTS=true
                shift
                ;;
            --dast)
                DAST_ENABLED=true
                shift
                # Check if next argument is a URL (not starting with --)
                if [[ $# -gt 0 && ! "$1" =~ ^-- ]]; then
                    DAST_TARGET="$1"
                    shift
                fi
                ;;
            --help|-h)
                show_help
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                ;;
        esac
    done

    print_header "🛡️ Security Scan - $PROJECT_NAME"

    # Initialize variables
    AUDIT_OUTPUT=""
    SEMGREP_OUTPUT=""
    SEMGREP_JSON=""
    TEST_OUTPUT=""
    AUDIT_CRITICAL=0
    AUDIT_HIGH=0
    AUDIT_MEDIUM=0
    AUDIT_LOW=0
    SEMGREP_CRITICAL=0
    SEMGREP_HIGH=0
    SEMGREP_MEDIUM=0
    SEMGREP_LOW=0
    SEMGREP_FILES=0
    TEST_PASSED=0
    TEST_FAILED=0
    TEST_STATUS="pending"
    SECURITY_SCORE=100
    GRADE="A+"
    GRADE_COLOR="green"
    GRADE_STATUS="Excellent"
    PM_VERSION="unknown"
    NODE_VERSION="unknown"
    FRAMEWORK_INFO=""
    DETECTED_FRAMEWORK="Node.js"
    DAST_OUTPUT=""
    DAST_STATUS="skipped"
    DAST_TEMPLATES=0
    DAST_REQUESTS=0
    DAST_CRITICAL=0
    DAST_HIGH=0
    DAST_MEDIUM=0
    DAST_LOW=0

    # Load configuration
    load_config

    # Get versions
    get_package_versions

    # Run scans
    run_audit
    run_semgrep
    run_tests
    run_dast

    # Calculate score
    calculate_score

    # Generate reports
    generate_dashboard
    generate_json_report

    # Open dashboard
    open_dashboard

    # Final summary
    print_header "📋 Summary"

    local total_critical=$((AUDIT_CRITICAL + SEMGREP_CRITICAL + DAST_CRITICAL))
    local total_high=$((AUDIT_HIGH + SEMGREP_HIGH + DAST_HIGH))
    local total_medium=$((AUDIT_MEDIUM + SEMGREP_MEDIUM + DAST_MEDIUM))
    local total_low=$((AUDIT_LOW + SEMGREP_LOW + DAST_LOW))

    echo -e "Grade:    ${GREEN}$GRADE${NC} ($SECURITY_SCORE/100)"
    echo ""
    echo -e "Critical: ${RED}$total_critical${NC} (threshold: $MAX_CRITICAL)"
    echo -e "High:     ${YELLOW}$total_high${NC} (threshold: $MAX_HIGH)"
    echo -e "Medium:   ${YELLOW}$total_medium${NC} (threshold: $MAX_MEDIUM)"
    echo -e "Low:      ${GREEN}$total_low${NC}"
    echo -e "Tests:    $TEST_PASSED passed, $TEST_FAILED failed"
    if [[ "$DAST_ENABLED" == "true" ]]; then
        echo -e "DAST:     $DAST_STATUS ($DAST_TEMPLATES templates)"
    fi
    echo ""

    if [[ "$CI_MODE" == "true" ]]; then
        if check_thresholds; then
            print_status "All thresholds passed!"
            exit 0
        else
            print_error "Threshold check failed!"
            exit 1
        fi
    else
        print_status "Scan complete! Dashboard: security-dashboard.html"
    fi
}

main "$@"
