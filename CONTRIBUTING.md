# Contributing to Childermass

Thank you for considering contributing to Childermass! This document provides guidelines and instructions for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Security Guidelines](#security-guidelines)
- [Pull Request Process](#pull-request-process)
- [Commit Message Guidelines](#commit-message-guidelines)

## Code of Conduct

This project adheres to professional standards:
- Be respectful and constructive
- Focus on what is best for the project
- Show empathy towards others
- Accept constructive criticism gracefully

## Getting Started

### Prerequisites

- Python 3.12 or higher
- Git
- Virtual environment tool (venv, virtualenv, or conda)

### Setup Development Environment

```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/Home.git
cd Home

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install development dependencies
make install-all

# 4. Set up pre-commit hooks (optional but recommended)
make setup-pre-commit

# 5. Verify setup
make check
```

## Development Workflow

### 1. Create a Branch

```bash
# Create feature branch from main
git checkout main
git pull origin main
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/bug-description
```

### 2. Make Changes

Follow the coding standards and ensure:
- Code is properly formatted
- Tests are added/updated
- Documentation is updated
- No secrets or credentials are committed

### 3. Run Tests Locally

```bash
# Quick check
make check

# Full CI pipeline
make ci

# Or individual steps
make format          # Auto-format code
make lint            # Check linting
make type-check      # Run type checking
make test-cov        # Run tests with coverage
make security        # Security scans
```

### 4. Commit Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat(calendar_mcp): add recurring event support"
```

See [Commit Message Guidelines](#commit-message-guidelines) for format.

### 5. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
```

## Coding Standards

### Python Style Guide

We follow PEP 8 with some modifications:
- Line length: 100 characters (not 79)
- Use double quotes for strings
- Use type hints where appropriate

### Automated Formatting

All code is automatically formatted using:
- **Ruff**: Fast linter and formatter
- **Black**: Code formatter
- **isort**: Import sorting

Run: `make format`

### Type Hints

Use type hints for function signatures:

```python
def create_event(
    summary: str,
    start_time: datetime,
    end_time: datetime,
    description: str | None = None
) -> dict[str, Any]:
    """Create a calendar event.
    
    Args:
        summary: Event title
        start_time: Event start datetime
        end_time: Event end datetime
        description: Optional event description
        
    Returns:
        Created event data
        
    Raises:
        ValueError: If dates are invalid
        SecurityError: If input validation fails
    """
    ...
```

### Documentation

- All public functions/classes must have docstrings
- Use Google-style docstrings
- Include examples for complex functionality
- Update README.md when adding features

Example:

```python
def validate_email(email: str) -> str:
    """Validate and normalize an email address.
    
    Args:
        email: Email address to validate
        
    Returns:
        Normalized email address
        
    Raises:
        SecurityError: If email format is invalid
        
    Example:
        >>> validate_email("user@example.com")
        'user@example.com'
        >>> validate_email("INVALID")
        SecurityError: Invalid email format
    """
    ...
```

## Testing Requirements

### Test Coverage

- Minimum 80% code coverage for new code
- All new features must include tests
- Bug fixes must include regression tests

### Test Structure

```python
# tests/test_feature.py
import pytest
from childermass.module import function

class TestFeature:
    """Test suite for feature X."""
    
    def test_basic_functionality(self):
        """Test basic case."""
        result = function("input")
        assert result == "expected"
    
    def test_edge_case(self):
        """Test edge case."""
        with pytest.raises(ValueError):
            function("invalid")
    
    @pytest.mark.integration
    def test_integration(self):
        """Test integration with external service."""
        # Use mocks for external calls
        ...
```

### Test Markers

Use pytest markers to categorize tests:

```python
@pytest.mark.unit           # Unit test
@pytest.mark.integration    # Integration test
@pytest.mark.slow           # Slow-running test
@pytest.mark.security       # Security-related test
```

### Running Tests

```bash
# All tests
make test

# With coverage
make test-cov

# Specific MCP server
make test-calendar

# Specific marker
pytest -m unit
pytest -m "not slow"
```

## Security Guidelines

### Never Commit Secrets

**NEVER** commit:
- API keys
- Passwords
- Tokens
- Credentials
- Personal data
- Configuration with sensitive info

Use:
- Environment variables
- Keyring/Keychain
- Configuration files (in .gitignore)

### Input Validation

Always validate and sanitize user input:

```python
from childermass.module.security import (
    validate_calendar_id,
    sanitize_text,
    SecurityError
)

def process_input(user_input: str) -> str:
    """Process user input safely."""
    try:
        validated = sanitize_text(user_input)
        return validated
    except SecurityError as e:
        logger.error(f"Security validation failed: {e}")
        raise
```

### Security Testing

- Run security scans: `make security`
- Test for injection vulnerabilities
- Validate all external inputs
- Test error handling

### Reporting Security Issues

**Do NOT create public issues for security vulnerabilities.**

Instead:
1. Email security concerns to the maintainer
2. Include detailed description
3. Wait for response before disclosure

See [SECURITY.md](SECURITY.md) for details.

## Pull Request Process

### Before Submitting

- [ ] Code follows style guidelines
- [ ] All tests pass locally
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] No merge conflicts
- [ ] Secrets/credentials removed
- [ ] Commit messages follow conventions

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change (fix or feature causing existing functionality to break)
- [ ] Documentation update

## Testing
Describe testing performed:
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] All CI checks pass
```

### Review Process

1. Automated checks run (CI/CD pipeline)
2. Code review by maintainer(s)
3. Address feedback
4. Approval and merge

### After Merge

- Delete your feature branch
- Update your local main branch
- Celebrate! 🎉

## Commit Message Guidelines

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, missing semicolons, etc.)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks
- **perf**: Performance improvements
- **ci**: CI/CD changes
- **security**: Security improvements

### Scope

Optional, specifies affected component:
- `calendar_mcp`
- `gmail_mcp`
- `weather_mcp`
- `ci`
- `docs`
- etc.

### Examples

```bash
# Feature
git commit -m "feat(calendar_mcp): add recurring event support"

# Bug fix
git commit -m "fix(gmail_mcp): handle empty attachment list"

# Documentation
git commit -m "docs: update installation instructions"

# Breaking change
git commit -m "feat(api)!: change authentication method

BREAKING CHANGE: All MCP servers now require OAuth2 instead of API keys"

# Multiple changes
git commit -m "chore: update dependencies and improve docs

- Update google-api-python-client to 2.190.0
- Fix typos in README.md
- Add examples to CONTRIBUTING.md"
```

## Adding a New MCP Server

### Structure

```
src/childermass/new_mcp/
├── __init__.py           # Package metadata
├── server.py             # MCP server implementation
├── client.py             # External service client
├── auth.py               # Authentication management
├── security.py           # Input validation
├── requirements.txt      # Dependencies
├── setup.sh              # Installation script
├── README.md             # Documentation
├── CHANGELOG.md          # Version history
└── tests/
    ├── __init__.py
    ├── test_server.py
    ├── test_client.py
    ├── test_security.py
    └── test_auth.py
```

### Checklist

- [ ] All required files present
- [ ] Tests with >80% coverage
- [ ] Security validation implemented
- [ ] Documentation complete
- [ ] Setup script tested
- [ ] Added to CI workflow (`.github/workflows/ci.yml`)
- [ ] Added to Dependabot (`.github/dependabot.yml`)
- [ ] README.md updated

### Template

See existing MCP servers (e.g., `calendar_mcp`) as reference implementation.

## Questions?

- Check [docs/CI_CD.md](docs/CI_CD.md) for CI/CD documentation
- Review existing code for patterns
- Open a discussion on GitHub
- Contact maintainers

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes for significant contributions
- Project documentation

Thank you for contributing! 🙏
