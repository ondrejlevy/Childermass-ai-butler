# Changelog

## [2.0.0] - 2026-02-13

### Security Hardening Release

#### Added
- **security.py**: Complete input validation module
  - Email validation with injection detection
  - File path validation with traversal prevention
  - MIME type whitelist + dangerous type blocking
  - Attachment size validation (25 MB / 35 MB total)
  - Subject/body length validation
  - Gmail query sanitization
  - Message ID / Label ID format validation
  - Filename sanitization
  - Error message sanitization (credential leak prevention)
- **Rate limiter**: Token bucket algorithm, per-account per-operation
- **Audit logger**: Structured JSON logging to `~/.childermass/gmail-audit.log`
- **Keyring integration**: macOS Keychain / Linux Secret Service token storage
- **Token migration**: `--migrate-keyring` CLI command
- **Account revocation**: `--revoke` CLI command
- **Test suite**: 92 tests covering all security features
- **Setup script**: One-command setup with validation

#### Changed
- **client.py**: All public functions now validate inputs before API calls
- **server.py**: All tools wrapped with error sanitization
- **auth.py**: Tokens stored in keyring first, file backup with chmod 600
- **OpenCode config**: Uses venv Python path directly

#### Security Fixes
- P0: Input validation on all write operations (send, reply, forward, draft)
- P0: Token storage moved from plaintext files to system keyring
- P0: Error messages sanitized to prevent credential leaks
- P1: Rate limiting prevents API quota exhaustion
- P1: Audit logging for all sensitive operations
- P1: MIME type validation blocks dangerous attachments
- P1: Attachment size limits enforced

## [1.0.0] - 2026-02-12

### Initial Release
- 13 Gmail tools via FastMCP
- Multi-account OAuth2 authentication
- RFC 5322 compliant email threading
- Attachment management (upload, download, forward)
- Auto-detect account for replies
