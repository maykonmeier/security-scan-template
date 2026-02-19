#!/bin/bash
#
# Security Scan Script - Universal Node.js/TypeScript Security Scanner
# https://github.com/maykonmeier/security-scan-template
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

show_help() {
    cat << EOF
Security Scan - Universal Node.js/TypeScript Security Scanner

Usage:
    bash security/scan.sh [options]

Options:
    --ci          Run in CI mode (no browser, exit codes based on thresholds)
    --json-only   Only generate JSON report, skip HTML dashboard
    --no-tests    Skip running tests
    --help        Show this help message

Configuration:
    Edit security/config.json to customize:
    - projectName: Name shown in dashboard
    - packageManager: npm, pnpm, yarn, bun, or auto (detect)
    - testCommand: npm script to run tests (default: test)
    - excludePaths: Paths to exclude from scanning
    - thresholds: Max allowed vulnerabilities per severity

Examples:
    bash security/scan.sh           # Run locally, open dashboard
    bash security/scan.sh --ci      # Run in CI, check thresholds

EOF
    exit 0
}

# ==============================================================================
# Load Configuration
# ==============================================================================

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        print_status "Loading configuration from config.json"

        # Parse JSON config (works on macOS and Linux)
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
        # Default to npm if no lock file found
        echo "npm"
    fi
}

# ==============================================================================
# Run Dependency Audit
# ==============================================================================

run_audit() {
    print_header "🔍 Dependency Audit"

    local pm=$(detect_package_manager)
    print_status "Detected package manager: $pm"

    cd "$PROJECT_ROOT"

    local audit_output=""
    local audit_json=""

    case "$pm" in
        pnpm)
            audit_output=$(pnpm audit 2>&1 || true)
            audit_json=$(pnpm audit --json 2>/dev/null || echo '{"advisories":{}}')
            ;;
        npm)
            audit_output=$(npm audit 2>&1 || true)
            audit_json=$(npm audit --json 2>/dev/null || echo '{"vulnerabilities":{}}')
            ;;
        yarn)
            audit_output=$(yarn audit 2>&1 || true)
            audit_json=$(yarn audit --json 2>/dev/null || echo '{}')
            ;;
        bun)
            # Bun doesn't have native audit, use npm
            print_warning "Bun doesn't have native audit, using npm audit"
            audit_output=$(npm audit 2>&1 || true)
            audit_json=$(npm audit --json 2>/dev/null || echo '{"vulnerabilities":{}}')
            ;;
    esac

    echo "$audit_output"

    # Parse vulnerabilities
    AUDIT_CRITICAL=0
    AUDIT_HIGH=0
    AUDIT_MEDIUM=0
    AUDIT_LOW=0

    if command -v python3 &> /dev/null; then
        # Try to parse based on package manager format
        case "$pm" in
            pnpm)
                AUDIT_CRITICAL=$(echo "$audit_output" | grep -c "critical" || echo "0")
                AUDIT_HIGH=$(echo "$audit_output" | grep -c "high" || echo "0")
                AUDIT_MEDIUM=$(echo "$audit_output" | grep -c "moderate" || echo "0")
                AUDIT_LOW=$(echo "$audit_output" | grep -c "low" || echo "0")
                ;;
            npm)
                if echo "$audit_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('metadata',{}).get('vulnerabilities',{}))" 2>/dev/null | grep -q "{"; then
                    AUDIT_CRITICAL=$(echo "$audit_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('metadata',{}).get('vulnerabilities',{}).get('critical',0))" 2>/dev/null || echo "0")
                    AUDIT_HIGH=$(echo "$audit_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('metadata',{}).get('vulnerabilities',{}).get('high',0))" 2>/dev/null || echo "0")
                    AUDIT_MEDIUM=$(echo "$audit_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('metadata',{}).get('vulnerabilities',{}).get('moderate',0))" 2>/dev/null || echo "0")
                    AUDIT_LOW=$(echo "$audit_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('metadata',{}).get('vulnerabilities',{}).get('low',0))" 2>/dev/null || echo "0")
                fi
                ;;
        esac
    fi

    # Fallback: parse text output
    if [[ "$AUDIT_CRITICAL" == "0" && "$AUDIT_HIGH" == "0" ]]; then
        AUDIT_CRITICAL=$(echo "$audit_output" | grep -oE '[0-9]+ critical' | head -1 | grep -oE '[0-9]+' || echo "0")
        AUDIT_HIGH=$(echo "$audit_output" | grep -oE '[0-9]+ high' | head -1 | grep -oE '[0-9]+' || echo "0")
        AUDIT_MEDIUM=$(echo "$audit_output" | grep -oE '[0-9]+ moderate' | head -1 | grep -oE '[0-9]+' || echo "0")
        AUDIT_LOW=$(echo "$audit_output" | grep -oE '[0-9]+ low' | head -1 | grep -oE '[0-9]+' || echo "0")
    fi

    # Ensure numeric values (remove newlines, whitespace, and leading zeros)
    sanitize_number() {
        local val
        val=$(echo "$1" | tr -d '\n\r ' | grep -oE '[0-9]+' | head -1)
        echo "${val:-0}"
    }

    AUDIT_CRITICAL=$(sanitize_number "$AUDIT_CRITICAL")
    AUDIT_HIGH=$(sanitize_number "$AUDIT_HIGH")
    AUDIT_MEDIUM=$(sanitize_number "$AUDIT_MEDIUM")
    AUDIT_LOW=$(sanitize_number "$AUDIT_LOW")

    AUDIT_OUTPUT="$audit_output"

    print_status "Audit complete: $AUDIT_CRITICAL critical, $AUDIT_HIGH high, $AUDIT_MEDIUM medium, $AUDIT_LOW low"
}

# ==============================================================================
# Run Semgrep
# ==============================================================================

run_semgrep() {
    print_header "🔬 Static Analysis (Semgrep)"

    if ! command -v semgrep &> /dev/null; then
        print_warning "Semgrep not installed. Install with: pip install semgrep"
        SEMGREP_OUTPUT="Semgrep not installed"
        SEMGREP_CRITICAL=0
        SEMGREP_HIGH=0
        SEMGREP_MEDIUM=0
        SEMGREP_LOW=0
        return
    fi

    cd "$PROJECT_ROOT"

    # Detect framework for optimal rules
    local semgrep_config="auto"
    if [[ -f "package.json" ]]; then
        if grep -q '"react"' package.json 2>/dev/null; then
            semgrep_config="p/react"
        elif grep -q '"express"' package.json 2>/dev/null; then
            semgrep_config="p/expressjs"
        elif grep -q '"next"' package.json 2>/dev/null; then
            semgrep_config="p/nextjs"
        fi
    fi

    print_status "Using Semgrep config: $semgrep_config"

    # Run semgrep with JSON output
    local semgrep_json
    semgrep_json=$(semgrep scan --config "$semgrep_config" --json --quiet 2>/dev/null || echo '{"results":[],"errors":[]}')

    # Also get text output for display
    SEMGREP_OUTPUT=$(semgrep scan --config "$semgrep_config" --quiet 2>&1 || true)

    if [[ -n "$SEMGREP_OUTPUT" && "$SEMGREP_OUTPUT" != *"No issues found"* ]]; then
        echo "$SEMGREP_OUTPUT"
    else
        print_status "No issues found"
    fi

    # Parse results
    SEMGREP_CRITICAL=0
    SEMGREP_HIGH=0
    SEMGREP_MEDIUM=0
    SEMGREP_LOW=0

    if command -v python3 &> /dev/null; then
        local counts
        counts=$(echo "$semgrep_json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    results = data.get('results', [])
    counts = {'ERROR': 0, 'WARNING': 0, 'INFO': 0}
    for r in results:
        sev = r.get('extra', {}).get('severity', 'INFO')
        counts[sev] = counts.get(sev, 0) + 1
    print(f\"{counts.get('ERROR', 0)} {counts.get('WARNING', 0)} {counts.get('INFO', 0)}\")
except:
    print('0 0 0')
" 2>/dev/null || echo "0 0 0")

        read -r SEMGREP_HIGH SEMGREP_MEDIUM SEMGREP_LOW <<< "$counts"
    fi

    SEMGREP_JSON="$semgrep_json"

    print_status "Semgrep complete: $SEMGREP_HIGH high, $SEMGREP_MEDIUM medium, $SEMGREP_LOW low"
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

    # Check if test script exists in package.json
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

    # Parse test results
    TEST_PASSED=$(echo "$TEST_OUTPUT" | grep -oE '[0-9]+ pass' | head -1 | grep -oE '[0-9]+' || echo "0")
    TEST_FAILED=$(echo "$TEST_OUTPUT" | grep -oE '[0-9]+ fail' | head -1 | grep -oE '[0-9]+' || echo "0")

    if [[ $test_result -eq 0 ]]; then
        TEST_STATUS="passed"
        print_status "Tests passed: $TEST_PASSED"
    else
        TEST_STATUS="failed"
        print_error "Tests failed: $TEST_FAILED failures"
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

    # Determine overall status
    local overall_status="success"
    local status_color="#22c55e"
    local status_text="All Clear"

    if [[ $total_critical -gt 0 ]]; then
        overall_status="critical"
        status_color="#ef4444"
        status_text="Critical Issues Found"
    elif [[ $total_high -gt $MAX_HIGH ]]; then
        overall_status="warning"
        status_color="#f59e0b"
        status_text="High Issues Exceed Threshold"
    elif [[ $total_high -gt 0 ]]; then
        overall_status="caution"
        status_color="#eab308"
        status_text="Issues Found"
    fi

    # Escape special characters for HTML
    local audit_html=$(echo "$AUDIT_OUTPUT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    local semgrep_html=$(echo "$SEMGREP_OUTPUT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    local test_html=$(echo "$TEST_OUTPUT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')

    cat > "$OUTPUT_DIR/security-dashboard.html" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard - $PROJECT_NAME</title>
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
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: .5; }
        }
        .animate-pulse-slow { animation: pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8 max-w-7xl">
        <!-- Header -->
        <header class="mb-8">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-3xl font-bold text-white">🛡️ Security Dashboard</h1>
                    <p class="text-gray-400 mt-1">$PROJECT_NAME</p>
                </div>
                <div class="text-right">
                    <p class="text-sm text-gray-400">Generated</p>
                    <p class="text-white font-mono">$(date '+%Y-%m-%d %H:%M:%S')</p>
                </div>
            </div>
        </header>

        <!-- Overall Status -->
        <div class="mb-8 p-6 rounded-xl" style="background: linear-gradient(135deg, ${status_color}22 0%, ${status_color}11 100%); border: 1px solid ${status_color}44;">
            <div class="flex items-center gap-4">
                <div class="w-16 h-16 rounded-full flex items-center justify-center" style="background: ${status_color}33;">
                    $(if [[ "$overall_status" == "success" ]]; then echo '<svg class="w-8 h-8" fill="none" stroke="'$status_color'" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>'; else echo '<svg class="w-8 h-8" fill="none" stroke="'$status_color'" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>'; fi)
                </div>
                <div>
                    <h2 class="text-2xl font-bold" style="color: ${status_color};">$status_text</h2>
                    <p class="text-gray-400">$total_critical critical, $total_high high, $total_medium medium, $total_low low</p>
                </div>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-400">Critical</p>
                        <p class="text-3xl font-bold text-critical">$total_critical</p>
                    </div>
                    <div class="w-12 h-12 bg-critical/20 rounded-lg flex items-center justify-center">
                        <span class="text-2xl">🚨</span>
                    </div>
                </div>
                <p class="text-xs text-gray-500 mt-2">Threshold: $MAX_CRITICAL</p>
            </div>

            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-400">High</p>
                        <p class="text-3xl font-bold text-high">$total_high</p>
                    </div>
                    <div class="w-12 h-12 bg-high/20 rounded-lg flex items-center justify-center">
                        <span class="text-2xl">⚠️</span>
                    </div>
                </div>
                <p class="text-xs text-gray-500 mt-2">Threshold: $MAX_HIGH</p>
            </div>

            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-400">Medium</p>
                        <p class="text-3xl font-bold text-medium">$total_medium</p>
                    </div>
                    <div class="w-12 h-12 bg-medium/20 rounded-lg flex items-center justify-center">
                        <span class="text-2xl">📋</span>
                    </div>
                </div>
                <p class="text-xs text-gray-500 mt-2">Threshold: $MAX_MEDIUM</p>
            </div>

            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-400">Low</p>
                        <p class="text-3xl font-bold text-low">$total_low</p>
                    </div>
                    <div class="w-12 h-12 bg-low/20 rounded-lg flex items-center justify-center">
                        <span class="text-2xl">ℹ️</span>
                    </div>
                </div>
                <p class="text-xs text-gray-500 mt-2">Informational</p>
            </div>
        </div>

        <!-- Test Status -->
        <div class="mb-8 bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h3 class="text-lg font-semibold mb-4 flex items-center gap-2">
                🧪 Test Results
                <span class="px-2 py-1 rounded text-xs $(if [[ "$TEST_STATUS" == "passed" ]]; then echo 'bg-green-500/20 text-green-400'; elif [[ "$TEST_STATUS" == "skipped" ]]; then echo 'bg-gray-500/20 text-gray-400'; else echo 'bg-red-500/20 text-red-400'; fi)">
                    $TEST_STATUS
                </span>
            </h3>
            <div class="grid grid-cols-2 gap-4">
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <p class="text-sm text-gray-400">Passed</p>
                    <p class="text-2xl font-bold text-green-400">$TEST_PASSED</p>
                </div>
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <p class="text-sm text-gray-400">Failed</p>
                    <p class="text-2xl font-bold text-red-400">$TEST_FAILED</p>
                </div>
            </div>
        </div>

        <!-- Detailed Results -->
        <div class="space-y-6">
            <!-- Dependency Audit -->
            <details class="bg-gray-800 rounded-xl border border-gray-700" open>
                <summary class="p-6 cursor-pointer hover:bg-gray-700/50 rounded-xl">
                    <h3 class="text-lg font-semibold inline-flex items-center gap-2">
                        📦 Dependency Audit
                        <span class="px-2 py-1 rounded text-xs bg-blue-500/20 text-blue-400">
                            $AUDIT_CRITICAL critical, $AUDIT_HIGH high
                        </span>
                    </h3>
                </summary>
                <div class="px-6 pb-6">
                    <pre class="bg-gray-900 rounded-lg p-4 text-sm text-gray-300 overflow-x-auto max-h-96 overflow-y-auto">$audit_html</pre>
                </div>
            </details>

            <!-- Semgrep Analysis -->
            <details class="bg-gray-800 rounded-xl border border-gray-700" open>
                <summary class="p-6 cursor-pointer hover:bg-gray-700/50 rounded-xl">
                    <h3 class="text-lg font-semibold inline-flex items-center gap-2">
                        🔬 Static Analysis (Semgrep)
                        <span class="px-2 py-1 rounded text-xs bg-purple-500/20 text-purple-400">
                            $SEMGREP_HIGH high, $SEMGREP_MEDIUM medium
                        </span>
                    </h3>
                </summary>
                <div class="px-6 pb-6">
                    <pre class="bg-gray-900 rounded-lg p-4 text-sm text-gray-300 overflow-x-auto max-h-96 overflow-y-auto">$semgrep_html</pre>
                </div>
            </details>

            <!-- Test Output -->
            <details class="bg-gray-800 rounded-xl border border-gray-700">
                <summary class="p-6 cursor-pointer hover:bg-gray-700/50 rounded-xl">
                    <h3 class="text-lg font-semibold inline-flex items-center gap-2">
                        🧪 Test Output
                        <span class="px-2 py-1 rounded text-xs $(if [[ "$TEST_STATUS" == "passed" ]]; then echo 'bg-green-500/20 text-green-400'; else echo 'bg-red-500/20 text-red-400'; fi)">
                            $TEST_PASSED passed, $TEST_FAILED failed
                        </span>
                    </h3>
                </summary>
                <div class="px-6 pb-6">
                    <pre class="bg-gray-900 rounded-lg p-4 text-sm text-gray-300 overflow-x-auto max-h-96 overflow-y-auto">$test_html</pre>
                </div>
            </details>
        </div>

        <!-- Thresholds -->
        <div class="mt-8 bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h3 class="text-lg font-semibold mb-4">📏 Configured Thresholds</h3>
            <div class="grid grid-cols-3 gap-4 text-center">
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <p class="text-sm text-gray-400">Max Critical</p>
                    <p class="text-xl font-bold $(if [[ $total_critical -gt $MAX_CRITICAL ]]; then echo 'text-red-400'; else echo 'text-green-400'; fi)">$MAX_CRITICAL</p>
                    <p class="text-xs text-gray-500">Current: $total_critical</p>
                </div>
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <p class="text-sm text-gray-400">Max High</p>
                    <p class="text-xl font-bold $(if [[ $total_high -gt $MAX_HIGH ]]; then echo 'text-red-400'; else echo 'text-green-400'; fi)">$MAX_HIGH</p>
                    <p class="text-xs text-gray-500">Current: $total_high</p>
                </div>
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <p class="text-sm text-gray-400">Max Medium</p>
                    <p class="text-xl font-bold $(if [[ $total_medium -gt $MAX_MEDIUM ]]; then echo 'text-red-400'; else echo 'text-green-400'; fi)">$MAX_MEDIUM</p>
                    <p class="text-xs text-gray-500">Current: $total_medium</p>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <footer class="mt-8 text-center text-gray-500 text-sm">
            <p>Generated by <a href="https://github.com/maykonmeier/security-scan-template" class="text-blue-400 hover:underline">security-scan-template</a></p>
        </footer>
    </div>
</body>
</html>
EOF

    print_status "Dashboard generated: security-dashboard.html"
}

# ==============================================================================
# Generate JSON Report
# ==============================================================================

generate_json_report() {
    if [[ "$GENERATE_JSON" != "true" ]]; then
        return
    fi

    local total_critical=$((AUDIT_CRITICAL + SEMGREP_CRITICAL))
    local total_high=$((AUDIT_HIGH + SEMGREP_HIGH))
    local total_medium=$((AUDIT_MEDIUM + SEMGREP_MEDIUM))
    local total_low=$((AUDIT_LOW + SEMGREP_LOW))

    cat > "$OUTPUT_DIR/security-report.json" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "project": "$PROJECT_NAME",
  "summary": {
    "critical": $total_critical,
    "high": $total_high,
    "medium": $total_medium,
    "low": $total_low
  },
  "audit": {
    "critical": $AUDIT_CRITICAL,
    "high": $AUDIT_HIGH,
    "medium": $AUDIT_MEDIUM,
    "low": $AUDIT_LOW
  },
  "semgrep": {
    "critical": $SEMGREP_CRITICAL,
    "high": $SEMGREP_HIGH,
    "medium": $SEMGREP_MEDIUM,
    "low": $SEMGREP_LOW
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
    local total_critical=$((AUDIT_CRITICAL + SEMGREP_CRITICAL))
    local total_high=$((AUDIT_HIGH + SEMGREP_HIGH))
    local total_medium=$((AUDIT_MEDIUM + SEMGREP_MEDIUM))

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
    TEST_PASSED=0
    TEST_FAILED=0
    TEST_STATUS="pending"

    # Load configuration
    load_config

    # Run scans
    run_audit
    run_semgrep
    run_tests

    # Generate reports
    generate_dashboard
    generate_json_report

    # Open dashboard
    open_dashboard

    # Final summary
    print_header "📋 Summary"

    local total_critical=$((AUDIT_CRITICAL + SEMGREP_CRITICAL))
    local total_high=$((AUDIT_HIGH + SEMGREP_HIGH))
    local total_medium=$((AUDIT_MEDIUM + SEMGREP_MEDIUM))
    local total_low=$((AUDIT_LOW + SEMGREP_LOW))

    echo -e "Critical: ${RED}$total_critical${NC} (threshold: $MAX_CRITICAL)"
    echo -e "High:     ${YELLOW}$total_high${NC} (threshold: $MAX_HIGH)"
    echo -e "Medium:   ${YELLOW}$total_medium${NC} (threshold: $MAX_MEDIUM)"
    echo -e "Low:      ${GREEN}$total_low${NC}"
    echo -e "Tests:    $TEST_PASSED passed, $TEST_FAILED failed"
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
