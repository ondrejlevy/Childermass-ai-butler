# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :x:                |

**Note**: This project is currently in active development. We recommend always using the latest version from the main branch.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them responsibly by:

1. **Email**: Send details to the project maintainer (specify in your GitHub profile)
2. **GitHub Security Advisories**: Use the "Security" tab in the repository to privately report vulnerabilities

### What to Include

Please include the following information:
- Type of vulnerability
- Full paths of affected source file(s)
- Location of the affected code (tag/branch/commit/direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability
- Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity (see below)

### Severity Levels

- **Critical**: Fix within 24-48 hours
- **High**: Fix within 1 week
- **Medium**: Fix within 2-4 weeks
- **Low**: Fix in next planned release

## Security Features

This project implements multiple layers of security to protect your personal data and credentials:

### 1. Credential Management

#### Secure Storage
- **Google Services**: OAuth 2.0 tokens stored in system keyring (macOS Keychain, Linux Secret Service, Windows Credential Locker)
- **UniFi Services**: Credentials stored in native OS credential storage
- **API Keys**: Encrypted storage via Python `keyring` library
- **No Plaintext Storage**: No credentials are stored in configuration files or code

#### Authentication Flow
- OAuth 2.0 authorization code flow for Google services
- Automatic token refresh with secure token rotation
- Authorization scope limitation (principle of least privilege)

### 2. Input Validation & Sanitization

All MCP servers implement comprehensive input validation:

```
✓ Email address validation
✓ URL validation
✓ Field length limits (prevents buffer overflow)
✓ Character whitelisting
✓ HTML/script injection prevention
✓ Path traversal prevention
✓ SQL injection prevention (where applicable)
```

**Key Limits**:
- Event summaries: 1,024 characters
- Descriptions: 8,192 characters
- Search queries: 1,000 characters
- Email addresses: RFC 5321 compliant
- URLs: RFC 3986 compliant

### 3. Rate Limiting

Token bucket algorithm implementation per MCP server:
- Prevents abuse and DoS attacks
- Configurable per-operation limits
- Automatic backoff on rate limit exceeded
- Logged for audit purposes

**Default Limits**:
- API calls: 10 requests per second
- Burst capacity: 20 requests
- Cooldown: 60 seconds

### 4. Audit Logging

Structured JSON audit logs for all operations:
- User actions logged with timestamps
- Success/failure status tracking
- Sanitized error messages (no credential leakage)
- Log rotation to prevent disk filling
- Stored in `~/.childermass/<service>-audit.log`

**Logged Information**:
```json
{
  "timestamp": "2026-02-15T10:30:00Z",
  "operation": "create_event",
  "status": "success",
  "user": "system",
  "details": "Event created in Calendar"
}
```

### 5. Network Security

- **HTTPS Only**: All external API calls use TLS 1.2+
- **Certificate Validation**: SSL certificate verification enabled by default
- **Local Networks**: Support for self-signed certificates (UniFi) with warnings
- **No External Data Leakage**: Credentials never sent to third parties

### 6. Error Handling

- Sanitized error messages (credentials/tokens stripped)
- No stack traces exposed to end users
- Detailed errors logged locally for debugging
- Graceful degradation on service failures

## Security Best Practices

### For Users

1. **Keep Software Updated**
   ```bash
   git pull origin main
   pip install -r requirements.txt --upgrade
   ```

2. **Protect Configuration Files**
   - Never commit `.opencode/opencode.json`
   - Set restrictive file permissions: `chmod 600 .opencode/opencode.json`
   - Regularly rotate API keys and tokens

3. **Review Authorized Apps**
   - Periodically check [Google Account Permissions](https://myaccount.google.com/permissions)
   - Revoke access for unused applications

4. **Monitor Audit Logs**
   ```bash
   tail -f ~/.childermass/*-audit.log
   ```

5. **Use Separate Credentials**
   - Create dedicated service accounts where possible
   - Don't use personal admin credentials for automation

6. **Network Isolation**
   - Run on trusted networks only
   - Consider firewall rules for local services (UniFi)

### For Developers

1. **Dependency Management**
   - Regularly update dependencies: `pip install --upgrade`
   - Monitor security advisories for dependencies
   - Use `pip-audit` to scan for known vulnerabilities
   ```bash
   pip install pip-audit
   pip-audit
   ```

2. **Code Security**
   - Never hardcode credentials
   - Use environment variables or keyring for secrets
   - Validate all user inputs
   - Sanitize all outputs
   - Follow principle of least privilege

3. **Testing**
   - Write security tests for input validation
   - Test error handling with invalid inputs
   - Verify credential isolation between tests
   ```bash
   PYTHONPATH=src pytest src/childermass/*/tests/test_security.py -v
   ```

4. **Code Review**
   - All PRs require review
   - Focus on credential handling and input validation
   - Check for common vulnerabilities (OWASP Top 10)

## Known Limitations

### Out of Scope

The following are **not** covered by this project's security model:

- **Physical Security**: Protection of the machine running the agent
- **OS Security**: Host operating system vulnerabilities
- **Browser Security**: Security of OAuth authorization flow in browser
- **Third-Party Services**: Security of Google, UniFi, Mapy.cz, etc.
- **Network Security**: Man-in-the-middle attacks on your network
- **Social Engineering**: User being tricked into revealing credentials

### Architecture Assumptions

This project assumes:
- Trusted execution environment (your personal computer)
- Secure OS-level credential storage (keyring/keychain)
- User understands OAuth consent screens
- Network is reasonably secure (home/office)

### Not Suitable For

⚠️ This project is **NOT designed for**:
- Multi-tenant environments
- Public-facing deployments
- Enterprise production systems without additional security hardening
- Environments requiring audit compliance (SOC 2, ISO 27001, etc.)
- Handling highly sensitive data beyond personal information

## Security Considerations for Services

### Google Services (Gmail, Calendar, Tasks, Contacts, Keep)
- ✅ OAuth 2.0 authentication
- ✅ Refresh token rotation
- ✅ Scope-limited access
- ⚠️ Keep API is unofficial (use at own risk)

### UniFi Services (Protect, Network)
- ✅ Local network only (no cloud)
- ✅ HTTPS with optional self-signed cert support
- ⚠️ Self-signed certificates must be explicitly trusted
- ⚠️ Credentials stored in keyring

### Weather & Mapping Services
- ✅ API key authentication
- ✅ No personal data transmitted
- ✅ Rate limited
- ⚠️ API keys have usage limits

### Memory Service
- ✅ Local storage only
- ✅ Optional encryption at rest
- ⚠️ Database file permissions should be restricted

## Incident Response

If a security incident is confirmed:

1. **Assessment**: Severity evaluation within 24 hours
2. **Patch Development**: Fix development and testing
3. **Disclosure**: 
   - Private notification to known users
   - Public disclosure after patch availability
   - GitHub Security Advisory published
4. **Post-Mortem**: Incident analysis and prevention measures

## Security Updates

Security patches are released as soon as available:
- Critical: Immediate release
- High/Medium: Batched in regular releases
- Low: Included in next minor version

Subscribe to GitHub repository releases to receive notifications.

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Google API Security Best Practices](https://developers.google.com/identity/protocols/oauth2/production-readiness)
- [Python Security Guidelines](https://python.readthedocs.io/en/stable/library/security.html)
- [MCP Security Considerations](https://modelcontextprotocol.io/security)

## Questions?

For security questions that are not sensitive, please open a [GitHub Discussion](../../discussions).

---

**Last Updated**: February 15, 2026
