# Makefile for Childermass Project
# Provides convenient commands for development, testing, and CI/CD operations

.PHONY: help install lint format type-check test security clean all pre-commit

# Default Python version
PYTHON := python3.12
PIP := $(PYTHON) -m pip

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

# ===========================================================================
# Help
# ===========================================================================
help: ## Show this help message
	@echo "$(BLUE)Childermass Development Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# ===========================================================================
# Installation & Setup
# ===========================================================================
install: ## Install all development dependencies
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	$(PIP) install --upgrade pip
	$(PIP) install ruff black isort mypy pytest pytest-cov pytest-asyncio pytest-mock
	$(PIP) install bandit safety pip-audit pre-commit
	@echo "$(GREEN)✓ Development dependencies installed$(NC)"

install-mcp: ## Install dependencies for all MCP servers
	@echo "$(BLUE)Installing MCP server dependencies...$(NC)"
	@for req in src/childermass/*/requirements.txt; do \
		echo "$(YELLOW)Installing $$req$(NC)"; \
		$(PIP) install -r "$$req" || true; \
	done
	@echo "$(GREEN)✓ All MCP dependencies installed$(NC)"

install-all: install install-mcp ## Install all dependencies
	@echo "$(GREEN)✓ All dependencies installed$(NC)"

setup-pre-commit: ## Set up pre-commit hooks
	@echo "$(BLUE)Setting up pre-commit hooks...$(NC)"
	pre-commit install
	pre-commit install --hook-type commit-msg
	@echo "$(GREEN)✓ Pre-commit hooks installed$(NC)"

# ===========================================================================
# Code Quality
# ===========================================================================
format: ## Format code with ruff and black
	@echo "$(BLUE)Formatting code...$(NC)"
	ruff format src/
	black src/
	isort --profile black src/
	@echo "$(GREEN)✓ Code formatted$(NC)"

lint: ## Run linting checks (ruff)
	@echo "$(BLUE)Running linting checks...$(NC)"
	ruff check src/
	@echo "$(GREEN)✓ Linting complete$(NC)"

lint-fix: ## Run linting and auto-fix issues
	@echo "$(BLUE)Running linting with auto-fix...$(NC)"
	ruff check src/ --fix
	@echo "$(GREEN)✓ Linting and fixes complete$(NC)"

type-check: ## Run type checking with mypy
	@echo "$(BLUE)Running type checks...$(NC)"
	mypy src/ --ignore-missing-imports --no-strict-optional
	@echo "$(GREEN)✓ Type checking complete$(NC)"

# ===========================================================================
# Testing
# ===========================================================================
test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	pytest src/ -v
	@echo "$(GREEN)✓ Tests complete$(NC)"

test-cov: ## Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	pytest src/ -v --cov=src --cov-report=term-missing --cov-report=html --cov-report=xml
	@echo "$(GREEN)✓ Tests complete. Coverage report: htmlcov/index.html$(NC)"

test-fast: ## Run tests in parallel (requires pytest-xdist)
	@echo "$(BLUE)Running tests in parallel...$(NC)"
	pytest src/ -v -n auto
	@echo "$(GREEN)✓ Tests complete$(NC)"

test-unit: ## Run unit tests only
	@echo "$(BLUE)Running unit tests...$(NC)"
	pytest src/ -v -m unit
	@echo "$(GREEN)✓ Unit tests complete$(NC)"

test-integration: ## Run integration tests only
	@echo "$(BLUE)Running integration tests...$(NC)"
	pytest src/ -v -m integration
	@echo "$(GREEN)✓ Integration tests complete$(NC)"

# Test individual MCP servers
test-calendar: ## Test calendar_mcp
	@cd src/childermass/calendar_mcp && pytest tests/ -v --cov=.

test-contacts: ## Test contacts_mcp
	@cd src/childermass/contacts_mcp && pytest tests/ -v --cov=.

test-gmail: ## Test gmail_mcp
	@cd src/childermass/gmail_mcp && pytest tests/ -v --cov=.

test-keep: ## Test keep_mcp
	@cd src/childermass/keep_mcp && pytest tests/ -v --cov=.

test-mapy: ## Test mapy_mcp
	@cd src/childermass/mapy_mcp && pytest tests/ -v --cov=.

test-memory: ## Test memory_mcp
	@cd src/childermass/memory_mcp && pytest tests/ -v --cov=.

test-network: ## Test network_mcp
	@cd src/childermass/network_mcp && pytest tests/ -v --cov=.

test-places: ## Test places_mcp
	@cd src/childermass/places_mcp && pytest tests/ -v --cov=.

test-protect: ## Test protect_mcp
	@cd src/childermass/protect_mcp && pytest tests/ -v --cov=.

test-tasks: ## Test tasks_mcp
	@cd src/childermass/tasks_mcp && pytest tests/ -v --cov=.

test-weather: ## Test weather_mcp
	@cd src/childermass/weather_mcp && pytest tests/ -v --cov=.

# ===========================================================================
# Security
# ===========================================================================
security: security-bandit security-safety security-audit ## Run all security checks

security-bandit: ## Run Bandit security linter
	@echo "$(BLUE)Running Bandit security scan...$(NC)"
	bandit -r src/ -f txt || true
	bandit -r src/ -f json -o bandit-report.json || true
	@echo "$(GREEN)✓ Bandit scan complete$(NC)"

security-safety: ## Run Safety dependency checker
	@echo "$(BLUE)Running Safety dependency check...$(NC)"
	@for req in src/childermass/*/requirements.txt; do \
		echo "$(YELLOW)Checking $$req$(NC)"; \
		safety check -r "$$req" || true; \
	done
	@echo "$(GREEN)✓ Safety check complete$(NC)"

security-audit: ## Run pip-audit for vulnerabilities
	@echo "$(BLUE)Running pip-audit...$(NC)"
	@for req in src/childermass/*/requirements.txt; do \
		echo "$(YELLOW)Auditing $$req$(NC)"; \
		pip-audit -r "$$req" || true; \
	done
	@echo "$(GREEN)✓ pip-audit complete$(NC)"

security-secrets: ## Scan for secrets with TruffleHog
	@echo "$(BLUE)Scanning for secrets...$(NC)"
	@if command -v trufflehog &> /dev/null; then \
		trufflehog filesystem . --only-verified; \
		echo "$(GREEN)✓ Secret scan complete$(NC)"; \
	else \
		echo "$(RED)✗ TruffleHog not installed. Install: brew install trufflesecurity/trufflehog/trufflehog$(NC)"; \
	fi

# ===========================================================================
# Pre-commit
# ===========================================================================
pre-commit: ## Run all pre-commit hooks
	@echo "$(BLUE)Running pre-commit hooks...$(NC)"
	pre-commit run --all-files
	@echo "$(GREEN)✓ Pre-commit checks complete$(NC)"

pre-commit-update: ## Update pre-commit hooks to latest versions
	@echo "$(BLUE)Updating pre-commit hooks...$(NC)"
	pre-commit autoupdate
	@echo "$(GREEN)✓ Pre-commit hooks updated$(NC)"

# ===========================================================================
# Cleaning
# ===========================================================================
clean: ## Clean build artifacts and caches
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ htmlcov/ htmlcov-combined/ .coverage .coverage.* coverage.xml
	rm -f bandit-report.json junit.xml
	@echo "$(GREEN)✓ Cleaned$(NC)"

clean-all: clean ## Clean everything including venv (use with caution!)
	@echo "$(YELLOW)⚠ This will remove virtual environments!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		rm -rf venv/ .venv/; \
		echo "$(GREEN)✓ All cleaned$(NC)"; \
	else \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi

# ===========================================================================
# CI Simulation
# ===========================================================================
ci: clean format lint type-check test security ## Run full CI pipeline locally
	@echo "$(GREEN)✓✓✓ All CI checks passed! ✓✓✓$(NC)"

ci-quick: format lint test-fast ## Run quick CI checks (parallel tests, no security)
	@echo "$(GREEN)✓✓✓ Quick CI checks passed! ✓✓✓$(NC)"

# ===========================================================================
# Info
# ===========================================================================
info: ## Show project information
	@echo "$(BLUE)Childermass Project Information$(NC)"
	@echo ""
	@echo "Python version: $$($(PYTHON) --version)"
	@echo "Pip version: $$($(PIP) --version | cut -d' ' -f2)"
	@echo ""
	@echo "MCP Servers:"
	@for dir in src/childermass/*/; do \
		mcp=$$(basename "$$dir"); \
		if [ -f "$$dir/requirements.txt" ]; then \
			count=$$(wc -l < "$$dir/requirements.txt" | tr -d ' '); \
			echo "  - $$mcp ($$count dependencies)"; \
		fi; \
	done

# ===========================================================================
# Development Shortcuts
# ===========================================================================
check: lint type-check ## Quick code check (lint + type-check)
	@echo "$(GREEN)✓ Code checks passed$(NC)"

fix: format lint-fix ## Auto-fix all issues
	@echo "$(GREEN)✓ Code fixed and formatted$(NC)"

all: clean install-all format lint type-check test security ## Do everything
	@echo "$(GREEN)✓✓✓ Everything complete! ✓✓✓$(NC)"
