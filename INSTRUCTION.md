# Development Instructions for Childermass

## Project Definition

**Childermass** is a sophisticated personal home assistant agent built on the **Model Context Protocol (MCP)**. Named after John Childermass from 'Jonathan Strange & Mr Norrell', this project serves as a modular agent system that integrates with various smart home services, communication tools, and information sources.

### Core Architecture

The project consists of:
- **Main Agent (Childermass)**: Central orchestration and coordination
- **Specialized MCP Servers**: Domain-specific sub-agents for different services

### MCP Server Modules

Each MCP server is self-contained and provides specific functionality:

| MCP Server | Purpose | Integration |
|------------|---------|-------------|
| `calendar_mcp` | Calendar management | Google Calendar API |
| `contacts_mcp` | Contact management | Google Contacts API |
| `gmail_mcp` | Email operations | Gmail API |
| `keep_mcp` | Note management | Google Keep |
| `tasks_mcp` | Task management | Google Tasks API |
| `memory_mcp` | Persistent memory storage | Local storage |
| `network_mcp` | Network management | UniFi Network Controller |
| `protect_mcp` | Security cameras | UniFi Protect |
| `places_mcp` | Location services | Places API |
| `mapy_mcp` | Mapping services | Mapy.cz |
| `weather_mcp` | Weather information | Weather API |

### Technology Stack

- **Language**: Python 3.12+
- **Protocol**: Model Context Protocol (MCP)
- **Code Quality**: Ruff (linter/formatter), Black, isort
- **Type Checking**: MyPy
- **Testing**: pytest with coverage
- **Security**: Bandit, Safety, pip-audit
- **Build System**: setuptools with pyproject.toml

### Project Goals

1. **Modularity**: Each MCP server is independently deployable and maintainable
2. **Security**: Strong authentication, credential management, and security scanning
3. **Reliability**: Comprehensive testing and CI/CD pipelines
4. **Privacy**: Local-first approach with secure credential storage
5. **Extensibility**: Easy to add new MCP servers for additional services

---

## Testing Requirements

### Testing Philosophy

Testing is a **critical component** of this project. Every MCP server must maintain comprehensive test coverage to ensure reliability and security.

### Test Structure

Each MCP server contains a `tests/` directory with:

```
src/childermass/<mcp_name>/
├── tests/
│   ├── __init__.py
│   ├── test_security.py      # Security-focused tests
│   ├── test_auth.py           # Authentication tests (if applicable)
│   ├── test_client.py         # Client functionality tests
│   └── test_server.py         # Server functionality tests
```

### Types of Tests

1. **Unit Tests**: Test individual functions and methods in isolation
2. **Integration Tests**: Test interactions between components
3. **Security Tests**: Validate security controls (credential handling, input validation, etc.)
4. **Functional Tests**: End-to-end testing of MCP server functionality

### Test Markers

Use pytest markers to categorize tests:

```python
@pytest.mark.unit
def test_parse_date():
    """Unit test example"""
    pass

@pytest.mark.integration
def test_api_integration():
    """Integration test example"""
    pass

@pytest.mark.security
def test_credential_masking():
    """Security test example"""
    pass
```

### Running Tests

#### All Tests
```bash
make test              # Run all tests
make test-cov          # Run with coverage report
make test-fast         # Run in parallel
```

#### Specific Test Categories
```bash
make test-unit         # Unit tests only
make test-integration  # Integration tests only
```

#### Individual MCP Server Tests
```bash
make test-calendar     # Test calendar_mcp
make test-gmail        # Test gmail_mcp
make test-network      # Test network_mcp
# ... etc.
```

#### Direct pytest
```bash
# Test specific MCP server
cd src/childermass/<mcp_name>
pytest tests/ -v --cov=.

# Test specific file
pytest tests/test_security.py -v

# Test specific function
pytest tests/test_security.py::test_credential_masking -v
```

### Coverage Requirements

- **Minimum Coverage**: 80% code coverage for each MCP server
- **Critical Paths**: 100% coverage for security-critical code (auth, credential handling)
- **Coverage Reports**: Generated in `htmlcov/index.html` after running `make test-cov`

### Test Best Practices

1. **Arrange-Act-Assert**: Structure tests clearly
2. **Mock External Dependencies**: Use `pytest-mock` for API calls
3. **Descriptive Names**: Test names should describe what they test
4. **Independence**: Tests should not depend on each other
5. **Fast Execution**: Keep unit tests fast; mark slow tests appropriately
6. **Security Focus**: Always test credential handling and input validation

---

## ⚠️ MANDATORY: Pre-Commit Requirements

### **CRITICAL RULE: Before Every Commit**

After **ANY code modification**, you **MUST** run the following commands:

```bash
# 1. Run Ruff linting and formatting
make lint

# 2. Run all tests
make test
```

### Detailed Pre-Commit Workflow

#### 1. Format Code
```bash
make format
```
This runs:
- `ruff format` - Fast Python formatter
- `black` - Additional formatting
- `isort` - Import sorting

#### 2. Lint Code
```bash
make lint
```
This runs:
- `ruff check src/` - Comprehensive linting

If issues are found, auto-fix them:
```bash
make lint-fix
```

#### 3. Run Type Checking (Recommended)
```bash
make type-check
```

#### 4. Run All Tests
```bash
make test
```

Or with coverage:
```bash
make test-cov
```

#### 5. Run Security Checks (Required for production)
```bash
make security
```

### Quick Pre-Commit Check

Run everything at once:
```bash
make check
```

This executes:
1. Code formatting (`make format`)
2. Linting (`make lint`)
3. Type checking (`make type-check`)
4. All tests (`make test`)

### Full CI Pipeline

To replicate the CI pipeline locally:
```bash
make ci
```

This runs the complete set of checks including security scans.

---

## Development Workflow

### 1. Before Starting Work

```bash
# Update from main
git checkout main
git pull origin main

# Create feature branch
git checkout -b feature/your-feature-name
```

### 2. During Development

Write code following the project standards:
- Use type hints
- Add docstrings
- Follow PEP 8 (enforced by ruff)
- Handle errors appropriately
- Never commit credentials

### 3. Before Committing

**MANDATORY STEPS:**

```bash
# Format code
make format

# Lint code
make lint

# Fix any linting issues
make lint-fix

# Run tests
make test

# Check coverage (optional but recommended)
make test-cov
```

**ALL CHECKS MUST PASS** before committing!

### 4. Commit Changes

```bash
git add .
git commit -m "type(scope): description"
```

Commit types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `chore`: Maintenance tasks

### 5. Before Pushing

Run the full check again:
```bash
make check
```

### 6. Create Pull Request

Ensure your PR:
- Has all checks passing
- Includes tests for new functionality
- Updates relevant documentation
- Follows commit message conventions

---

## Code Quality Standards

### Linting Rules

The project uses **Ruff** for fast, comprehensive linting:

- Line length: 100 characters
- Python version: 3.12+
- Profile: Compatible with Black formatting
- All ruff rules are enforced (see `ruff.toml`)

### Type Checking

Use type hints everywhere:

```python
def process_event(event_id: str, user_id: int) -> dict[str, Any]:
    """Process an event with proper type hints."""
    pass
```

### Security Rules

1. **Never commit credentials** - Use environment variables or secure vaults
2. **Validate all inputs** - Sanitize user input and API responses
3. **Handle sensitive data carefully** - Mask/redact in logs
4. **Use secure dependencies** - Keep dependencies updated and scanned

---

## Continuous Integration

### GitHub Actions CI Pipeline

Every push and PR triggers:

1. **Linting** - Ruff checks
2. **Type Checking** - MyPy validation
3. **Testing** - Full test suite with coverage
4. **Security Scanning** - Bandit, Safety, pip-audit
5. **Dependency Auditing** - Vulnerability checks

### Required Checks

All CI checks must pass before merging to `main`.

If CI fails:
1. Review the CI logs
2. Fix the issues locally
3. Run `make check` to verify
4. Commit and push fixes

---

## Summary Checklist

Before **every commit**, verify:

- [ ] Code is formatted (`make format`)
- [ ] Linting passes (`make lint`)
- [ ] All tests pass (`make test`)
- [ ] Type checking passes (`make type-check`) [recommended]
- [ ] No credentials in code
- [ ] Documentation is updated
- [ ] Commit message follows conventions

For **production releases**, additionally verify:

- [ ] Security scans pass (`make security`)
- [ ] Test coverage meets requirements (`make test-cov`)
- [ ] CHANGELOG updated (if applicable)
- [ ] Version bumped (if applicable)

---

## Quick Reference Commands

```bash
# Essential (run before every commit)
make format           # Format code
make lint            # Check linting
make test            # Run tests

# Comprehensive check
make check           # Format + Lint + Type-check + Test

# Full CI pipeline
make ci              # All checks including security

# Individual test suites
make test-<mcp_name> # Test specific MCP server
make test-cov        # Tests with coverage report

# Development helpers
make install-all     # Install all dependencies
make clean          # Clean build artifacts
make help           # Show all available commands
```

---

## Getting Help

- **Documentation**: See `README.md` and `CONTRIBUTING.md`
- **Security**: See `SECURITY.md` for security policies
- **CI/CD**: See `docs/CI_CD.md` for pipeline details
- **Code Issues**: Use `make check` to diagnose problems

Remember: **Quality code is tested code. Always run linting and tests before committing!**
