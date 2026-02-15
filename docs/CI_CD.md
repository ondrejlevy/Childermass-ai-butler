# CI/CD & Testing Documentation

## Overview

This document describes the Continuous Integration and Continuous Deployment (CI/CD) pipeline for the Childermass project, including all automated testing, security scanning, and code quality checks.

## 📋 Table of Contents

- [Workflows](#workflows)
- [Security Tools](#security-tools)
- [Code Quality Tools](#code-quality-tools)
- [Running Tests Locally](#running-tests-locally)
- [Dependabot](#dependabot)
- [Badges](#badges)

## 🔄 Workflows

### 1. CI Pipeline (`.github/workflows/ci.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Manual trigger via workflow_dispatch

**Jobs:**

#### Lint & Format Check
- **Ruff**: Fast Python linter (replaces Flake8, isort, pyupgrade)
- **Black**: Code formatter check
- **isort**: Import sorting check

#### Type Check (MyPy)
- Static type checking across all MCP servers
- Catches type-related bugs before runtime

#### Security Audit
- **pip-audit**: Scans dependencies for known vulnerabilities
- **Bandit**: Security-focused static analysis
- **Safety**: Additional dependency vulnerability check
- Generates security reports as artifacts

#### Test Matrix
- Runs tests for all 11 MCP servers in parallel:
  - calendar_mcp
  - contacts_mcp
  - gmail_mcp
  - keep_mcp
  - mapy_mcp
  - memory_mcp
  - network_mcp
  - places_mcp
  - protect_mcp
  - tasks_mcp
  - weather_mcp
- Each server tested independently with coverage reporting
- Results uploaded to Codecov

#### Coverage Report
- Combines coverage from all MCP servers
- Generates unified HTML report

#### Dependency Review
- Runs on pull requests only
- Checks for vulnerable or outdated dependencies

### 2. CodeQL Analysis (`.github/workflows/codeql.yml`)

**Triggers:**
- Push to `main` or `develop`
- Pull requests
- Weekly schedule (Mondays at 6:00 AM UTC)
- Manual trigger

**Features:**
- GitHub's semantic code analysis
- Extended security queries
- Automatic vulnerability detection
- Results visible in Security tab

### 3. OSSF Scorecard (`.github/workflows/scorecard.yml`)

**Triggers:**
- Weekly schedule (Mondays at 7:30 AM UTC)
- Push to `main`
- Branch protection rule changes
- Manual trigger

**Checks:**
- Security best practices
- Supply chain security
- Vulnerability management
- Code review practices
- Generates OpenSSF Scorecard badge

### 4. Secrets Scanning (`.github/workflows/secrets-scan.yml`)

**Triggers:**
- Push to `main` or `develop`
- Pull requests
- Daily schedule (2:00 AM UTC)
- Manual trigger

**Tools:**
- **TruffleHog**: Advanced secret detection
- **GitLeaks**: Git repository secret scanner

## 🔒 Security Tools

### pip-audit
Scans Python dependencies for known security vulnerabilities.

```bash
# Run locally for all MCP servers
for req in src/childermass/*/requirements.txt; do
    pip-audit -r "$req"
done
```

### Bandit
Security-oriented static analyzer for Python code.

```bash
# Run locally
bandit -r src/ -f txt
```

**Configuration:** See `pyproject.toml` `[tool.bandit]` section

### Safety
Checks Python dependencies against safety database.

```bash
# Run locally
for req in src/childermass/*/requirements.txt; do
    safety check -r "$req"
done
```

### TruffleHog & GitLeaks
Scan for accidentally committed secrets and credentials.

```bash
# Install TruffleHog
brew install trufflesecurity/trufflehog/trufflehog

# Run locally
trufflehog filesystem . --only-verified
```

### CodeQL
GitHub's semantic code analysis engine.
- Runs automatically via GitHub Actions
- View results in repository Security tab

## ✨ Code Quality Tools

### Ruff
Fast, modern Python linter written in Rust. Replaces multiple tools:
- Flake8
- isort
- pyupgrade
- And many more

```bash
# Install
pip install ruff

# Run checks
ruff check src/

# Auto-fix issues
ruff check src/ --fix

# Format code
ruff format src/
```

**Configuration:** `ruff.toml`

### Black
The uncompromising Python code formatter.

```bash
# Install
pip install black

# Check formatting
black --check src/

# Apply formatting
black src/
```

**Configuration:** `pyproject.toml` `[tool.black]` section

### isort
Import statement organizer.

```bash
# Install
pip install isort

# Check
isort --check-only --profile black src/

# Apply
isort --profile black src/
```

**Configuration:** `pyproject.toml` `[tool.isort]` section

### MyPy
Static type checker for Python.

```bash
# Install
pip install mypy

# Run type checking
mypy src/ --ignore-missing-imports
```

**Configuration:** `pyproject.toml` `[tool.mypy]` section

## 🧪 Running Tests Locally

### Prerequisites
```bash
# Activate virtual environment
source venv/bin/activate  # or: source .venv/bin/activate

# Install test dependencies
pip install pytest pytest-cov pytest-asyncio pytest-mock
```

### Run All Tests
```bash
# From project root
pytest src/ -v

# With coverage
pytest src/ --cov=src --cov-report=html --cov-report=term
```

### Run Tests for Specific MCP Server
```bash
# Navigate to MCP server directory
cd src/childermass/calendar_mcp

# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=. --cov-report=html
```

### Run Specific Test Categories
```bash
# Unit tests only
pytest -m unit

# Skip slow tests
pytest -m "not slow"

# Security tests
pytest -m security

# Integration tests
pytest -m integration
```

### Test Configuration
See `pyproject.toml` `[tool.pytest.ini_options]` section for:
- Test discovery patterns
- Coverage settings
- Markers
- Warning filters

## 🤖 Dependabot

Dependabot automatically checks for dependency updates and creates pull requests.

**Configuration:** `.github/dependabot.yml`

**Schedule:**
- **GitHub Actions**: Weekly on Mondays
- **Python dependencies**: Weekly on Tuesday-Friday (staggered by MCP server)

**Benefits:**
- Automatic security updates
- Keeps dependencies current
- Reduces maintenance burden

### Dependabot PR Management
```bash
# Review Dependabot PRs
# 1. Check the changelog/release notes
# 2. Review CI test results
# 3. Approve and merge if all checks pass

# Group update strategy
# Dependabot will create separate PRs for each MCP server
# This allows granular control and easier rollback if needed
```

## 📊 Badges

Add these badges to your README.md:

```markdown
![CI Pipeline](https://github.com/YOUR_USERNAME/YOUR_REPO/workflows/CI%20Pipeline/badge.svg)
![CodeQL](https://github.com/YOUR_USERNAME/YOUR_REPO/workflows/CodeQL/badge.svg)
![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/YOUR_USERNAME/YOUR_REPO/badge)
[![codecov](https://codecov.io/gh/YOUR_USERNAME/YOUR_REPO/branch/main/graph/badge.svg)](https://codecov.io/gh/YOUR_USERNAME/YOUR_REPO)
```

## 🔧 Local Development Workflow

### Before Committing
```bash
# 1. Format code
ruff format src/
black src/

# 2. Sort imports
isort --profile black src/

# 3. Lint
ruff check src/ --fix

# 4. Type check
mypy src/ --ignore-missing-imports

# 5. Run tests
pytest src/ -v

# 6. Security check
bandit -r src/
```

### Pre-commit Hook (Recommended)
Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
set -e

echo "Running pre-commit checks..."

# Format
ruff format src/
black src/

# Lint
ruff check src/

# Type check
mypy src/ --ignore-missing-imports

# Tests
pytest src/ -v

echo "✅ All checks passed!"
```

Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

## 🚀 Additional Tools to Consider

### 1. **pytest-xdist**
Parallelize test execution for faster CI.

```bash
pip install pytest-xdist
pytest -n auto
```

### 2. **pre-commit**
Manage and maintain pre-commit hooks.

```bash
pip install pre-commit
pre-commit install
```

### 3. **tox**
Test across multiple Python versions.

```bash
pip install tox
tox
```

### 4. **vulture**
Find dead (unused) Python code.

```bash
pip install vulture
vulture src/
```

### 5. **interrogate**
Check docstring coverage.

```bash
pip install interrogate
interrogate -v src/
```

### 6. **pyright**
Alternative to MyPy with different strengths.

```bash
npm install -g pyright
pyright src/
```

## 📝 Environment Variables for CI

The following secrets should be configured in GitHub repository settings:

- `CODECOV_TOKEN`: For coverage reporting
- `GITLEAKS_LICENSE`: (Optional) For GitLeaks Pro features

## 🐛 Troubleshooting

### Tests Failing Locally But Passing in CI
- Check Python version matches CI (3.12)
- Ensure all dependencies are installed
- Clear cache: `rm -rf .pytest_cache .mypy_cache .ruff_cache`

### Type Check Errors
- Add `# type: ignore` comment for unavoidable issues
- Update type stubs: `pip install types-*`

### Coverage Too Low
- Add tests for untested code
- Use `# pragma: no cover` for code that shouldn't be tested

## 📚 Resources

- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [MyPy Documentation](https://mypy.readthedocs.io/)
- [Pytest Documentation](https://docs.pytest.org/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [OSSF Scorecard](https://github.com/ossf/scorecard)
