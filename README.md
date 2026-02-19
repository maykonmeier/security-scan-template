# 🛡️ Security Scan Template

A universal security scanning solution for Node.js/TypeScript projects. Automatically detects your package manager, runs dependency audits, static analysis with Semgrep, and generates beautiful HTML dashboards.

## Features

- **🔍 Dependency Audit** - Scans for known vulnerabilities in dependencies
- **🔬 Static Analysis** - Uses Semgrep to find security issues in code
- **🧪 Test Integration** - Runs your test suite and reports results
- **📊 HTML Dashboard** - Beautiful, dark-mode dashboard with all results
- **📋 JSON Reports** - Machine-readable output for CI/CD integration
- **🚀 CI/CD Ready** - GitHub Actions workflow included
- **📦 Auto-Detection** - Works with npm, pnpm, yarn, and bun

## Quick Start

### Installation

**Option 1: One-liner (recommended)**

```bash
curl -sSL https://raw.githubusercontent.com/maykonmeier/security-scan-template/main/install.sh | bash
```

**Option 2: Clone and copy**

```bash
git clone https://github.com/maykonmeier/security-scan-template.git
cp -r security-scan-template/security ./
cp -r security-scan-template/.github ./
rm -rf security-scan-template
```

### Requirements

- **Node.js** 18+ (for your project)
- **Semgrep** for static analysis:
  ```bash
  pip install semgrep
  ```

### Run the Scanner

```bash
# Using npm/pnpm/yarn/bun
pnpm run security-scan

# Or directly
bash security/scan.sh
```

The scanner will:
1. Run dependency audit (npm/pnpm/yarn audit)
2. Run Semgrep static analysis
3. Run your test suite
4. Generate `security-dashboard.html`
5. Open the dashboard in your browser

## Configuration

Edit `security/config.json` to customize the scanner:

```json
{
  "projectName": "My Project",
  "packageManager": "auto",
  "testCommand": "test",
  "excludePaths": ["node_modules", "dist", ".git", "coverage"],
  "semgrepConfig": "auto",
  "generateJson": true,
  "openDashboard": true,
  "thresholds": {
    "maxCritical": 0,
    "maxHigh": 5,
    "maxMedium": 20
  }
}
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `projectName` | "My Project" | Name displayed in dashboard |
| `packageManager` | "auto" | Package manager to use (npm, pnpm, yarn, bun, or auto) |
| `testCommand` | "test" | npm script to run tests |
| `excludePaths` | [...] | Paths to exclude from scanning |
| `semgrepConfig` | "auto" | Semgrep ruleset (auto-detects framework) |
| `generateJson` | true | Generate security-report.json |
| `openDashboard` | true | Auto-open dashboard in browser |
| `thresholds.maxCritical` | 0 | Max allowed critical vulnerabilities |
| `thresholds.maxHigh` | 5 | Max allowed high vulnerabilities |
| `thresholds.maxMedium` | 20 | Max allowed medium vulnerabilities |

## CLI Options

```bash
# Local mode (default) - opens dashboard
bash security/scan.sh

# CI mode - no browser, exit codes based on thresholds
bash security/scan.sh --ci

# Skip tests
bash security/scan.sh --no-tests

# JSON only (no HTML dashboard)
bash security/scan.sh --json-only

# Show help
bash security/scan.sh --help
```

## CI/CD Integration

### GitHub Actions

The installer automatically adds `.github/workflows/security.yml` which:

- Runs on push to main/master/develop
- Runs on pull requests
- Runs weekly (Monday 6 AM UTC)
- Comments results on PRs
- Uploads reports as artifacts

### Manual Trigger

You can manually trigger the workflow from GitHub Actions with options to skip tests.

### Exit Codes

In CI mode (`--ci`), the script exits with:
- `0` - All thresholds passed
- `1` - Thresholds exceeded or tests failed

## Dashboard

The generated `security-dashboard.html` includes:

- **Overall Status** - Quick visual indicator
- **Summary Cards** - Critical, High, Medium, Low counts
- **Test Results** - Passed/Failed test counts
- **Detailed Findings** - Collapsible sections for each scan type
- **Threshold Status** - Shows current vs. allowed values

## Ignoring Files

Edit `security/.semgrepignore` to exclude files from Semgrep analysis. Common excludes are pre-configured:

- `node_modules/`, `dist/`, `build/`
- Test files (`*.test.ts`, `*.spec.ts`)
- Config files (`*.config.js`)
- Lock files

## Updating

To update to the latest version:

```bash
# Re-run the installer
curl -sSL https://raw.githubusercontent.com/maykonmeier/security-scan-template/main/install.sh | bash
```

Or manually update individual files from the repository.

## Troubleshooting

### Semgrep not found

Install Semgrep with pip:
```bash
pip install semgrep
# or
pip3 install semgrep
```

### Permission denied

Make the script executable:
```bash
chmod +x security/scan.sh
```

### No test script found

Either add a `test` script to your `package.json` or use `--no-tests`:
```bash
bash security/scan.sh --no-tests
```

### Dashboard not opening

The browser auto-open only works on macOS and Linux with a desktop environment. In headless environments or WSL, manually open the `security-dashboard.html` file.

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
