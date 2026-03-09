# Secrets Scanning Configuration

This document explains the Gitleaks configuration for the Childermass project.

## Overview

The project uses [Gitleaks](https://github.com/gitleaks/gitleaks) to scan for accidentally committed secrets, API keys, and credentials. The configuration is defined in `.gitleaks.toml`.

## Configuration Details

### Allowlisted Paths

The following paths are allowlisted to prevent false positives:
- `**/test_security.py` - Test files that intentionally contain mock credentials for testing sanitization logic
- `**/tests/**/*.py` - All test files that may include test credentials

### Allowlisted Patterns

Regex patterns that are ignored:
- `(test|fake|mock|example|dummy)[-_]?(key|token|secret|password)` - Test credential patterns
- `sk-[a-zA-Z0-9]{20,}` - Mock API keys used in tests

### Stopwords

If these words appear near a detected secret, it's likely a test value:
- test, example, mock, fake, dummy, sample, placeholder

## Inline Annotations

For additional safety, test files use inline `# gitleaks:allow` comments on lines with mock credentials:

```python
# Example from test_security.py
error = Exception("API key: sk-abc123def456 is invalid")  # gitleaks:allow
```

## Why Mock Credentials in Tests?

The `test_security.py` files test the **sanitization** of error messages to ensure real secrets are properly redacted. These tests require realistic-looking mock credentials to validate the sanitization logic works correctly.

## Verifying the Configuration

To test the Gitleaks configuration locally:

```bash
# Install gitleaks
brew install gitleaks  # macOS
# or download from https://github.com/gitleaks/gitleaks/releases

# Run scan
gitleaks detect --config .gitleaks.toml --verbose

# Scan specific paths
gitleaks detect --config .gitleaks.toml --source=src/
```

## GitHub Actions Integration

The secrets scanning workflow (`.github/workflows/secrets-scan.yml`) automatically uses the `.gitleaks.toml` configuration. No additional setup is required.

## Adding New Test Credentials

When adding new test credentials:

1. **Use obvious test patterns**: Include words like "test", "fake", "mock" in the value
2. **Add inline comment**: Append `# gitleaks:allow` to the line
3. **Document the purpose**: Add a comment explaining why the mock credential is needed

Example:

```python
def test_api_key_redaction():
    """Test that API keys are properly redacted from logs."""
    test_key = "test-api-key-not-real-12345678"  # gitleaks:allow - Mock key for testing redaction
    result = redact_sensitive_data(f"Using key: {test_key}")
    assert test_key not in result
```

## Security Best Practices

- Never commit real credentials, even temporarily
- Use environment variables or secret management for actual credentials
- Review secrets scanning results in pull requests
- Update `.gitleaks.toml` if legitimate patterns are being flagged

## References

- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [Gitleaks Configuration Guide](https://github.com/gitleaks/gitleaks#configuration)
- [Project Security Policy](SECURITY.md)
