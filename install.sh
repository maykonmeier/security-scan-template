#!/bin/bash
#
# Security Scan Template - Installer
# https://github.com/maykonmeier/security-scan-template
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/maykonmeier/security-scan-template/main/install.sh | bash
#
# Or locally:
#   bash install.sh
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

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

# Configuration
REPO_URL="https://github.com/maykonmeier/security-scan-template"
RAW_URL="https://raw.githubusercontent.com/maykonmeier/security-scan-template/main"
TARGET_DIR="$(pwd)"

print_header "🛡️ Security Scan Template Installer"

# Check if we're in a Node.js project
if [[ ! -f "$TARGET_DIR/package.json" ]]; then
    print_error "No package.json found in current directory"
    echo "Please run this installer from the root of your Node.js project"
    exit 1
fi

print_status "Found package.json"

# Create security directory
print_status "Creating security directory..."
mkdir -p "$TARGET_DIR/security"

# Download or copy files
if [[ -f "$(dirname "$0")/security/scan.sh" ]]; then
    # Local installation (from cloned repo)
    print_status "Installing from local files..."

    cp "$(dirname "$0")/security/scan.sh" "$TARGET_DIR/security/"
    cp "$(dirname "$0")/security/config.json" "$TARGET_DIR/security/"
    cp "$(dirname "$0")/security/.semgrepignore" "$TARGET_DIR/security/"

    mkdir -p "$TARGET_DIR/.github/workflows"
    cp "$(dirname "$0")/.github/workflows/security.yml" "$TARGET_DIR/.github/workflows/"
else
    # Remote installation (curl)
    print_status "Downloading from GitHub..."

    curl -sSL "$RAW_URL/security/scan.sh" -o "$TARGET_DIR/security/scan.sh"
    curl -sSL "$RAW_URL/security/config.json" -o "$TARGET_DIR/security/config.json"
    curl -sSL "$RAW_URL/security/.semgrepignore" -o "$TARGET_DIR/security/.semgrepignore"

    mkdir -p "$TARGET_DIR/.github/workflows"
    curl -sSL "$RAW_URL/.github/workflows/security.yml" -o "$TARGET_DIR/.github/workflows/security.yml"
fi

# Make scan.sh executable
chmod +x "$TARGET_DIR/security/scan.sh"
print_status "Made scan.sh executable"

# Detect project name from package.json
PROJECT_NAME=$(python3 -c "import json; print(json.load(open('package.json')).get('name', 'My Project'))" 2>/dev/null || echo "My Project")

# Update config.json with project name
if command -v python3 &> /dev/null; then
    python3 -c "
import json
with open('$TARGET_DIR/security/config.json', 'r') as f:
    config = json.load(f)
config['projectName'] = '$PROJECT_NAME'
with open('$TARGET_DIR/security/config.json', 'w') as f:
    json.dump(config, f, indent=2)
" 2>/dev/null || true
    print_status "Updated project name in config.json: $PROJECT_NAME"
fi

# Detect package manager and add script to package.json
PM="npm"
if [[ -f "pnpm-lock.yaml" ]]; then
    PM="pnpm"
elif [[ -f "yarn.lock" ]]; then
    PM="yarn"
elif [[ -f "bun.lockb" ]]; then
    PM="bun"
fi

# Add security-scan script to package.json
if command -v python3 &> /dev/null; then
    python3 -c "
import json
with open('package.json', 'r') as f:
    pkg = json.load(f)
if 'scripts' not in pkg:
    pkg['scripts'] = {}
if 'security-scan' not in pkg['scripts']:
    pkg['scripts']['security-scan'] = 'bash security/scan.sh'
    with open('package.json', 'w') as f:
        json.dump(pkg, f, indent=2)
    print('Added security-scan script')
else:
    print('security-scan script already exists')
" 2>/dev/null || true
fi
print_status "Added '$PM run security-scan' command"

# Update .gitignore
if [[ -f "$TARGET_DIR/.gitignore" ]]; then
    if ! grep -q "security-dashboard.html" "$TARGET_DIR/.gitignore" 2>/dev/null; then
        echo "" >> "$TARGET_DIR/.gitignore"
        echo "# Security scan outputs" >> "$TARGET_DIR/.gitignore"
        echo "security-dashboard.html" >> "$TARGET_DIR/.gitignore"
        echo "security-report.json" >> "$TARGET_DIR/.gitignore"
        print_status "Updated .gitignore"
    fi
else
    cat > "$TARGET_DIR/.gitignore" << 'EOF'
# Security scan outputs
security-dashboard.html
security-report.json
EOF
    print_status "Created .gitignore"
fi

# Print summary
print_header "✅ Installation Complete!"

echo "Files created:"
echo "  - security/scan.sh       (main scanner script)"
echo "  - security/config.json   (configuration)"
echo "  - security/.semgrepignore"
echo "  - .github/workflows/security.yml"
echo ""

echo -e "To run the security scan:"
echo -e "  ${CYAN}$PM run security-scan${NC}"
echo ""
echo -e "Or directly:"
echo -e "  ${CYAN}bash security/scan.sh${NC}"
echo ""

echo -e "Configuration:"
echo -e "  Edit ${CYAN}security/config.json${NC} to customize thresholds and settings"
echo ""

echo -e "Requirements:"
echo -e "  - Semgrep: ${CYAN}pip install semgrep${NC}"
echo ""

print_warning "Remember to commit the security/ folder and .github/workflows/ to your repository!"
echo ""
echo -e "For more information: ${BLUE}$REPO_URL${NC}"
