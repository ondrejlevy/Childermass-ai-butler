# Childermass Gmail MCP Server

Custom Gmail MCP server for OpenCode / Claude Code with integrated security hardening.

## Features

- **13 Gmail tools**: list, read, search, send, reply, reply-all, forward, draft, download attachment, labels, archive
- **Multi-account support**: authenticate multiple Gmail accounts
- **RFC 5322 threading**: proper In-Reply-To / References headers
- **Security hardened** (v2.0):
  - Input validation on all operations (email, path, MIME, query)
  - Keyring-based token storage (macOS Keychain / Linux Secret Service)
  - Token bucket rate limiting per account/operation
  - Structured JSON audit logging (`~/.childermass/gmail-audit.log`)
  - Error message sanitization (no credential leaks to LLM)
  - Attachment size/MIME type validation

## Quick Start

```bash
# 1. Setup
cd /Users/ondrej.levy/Agents/Home
./src/childermass/gmail_mcp/setup.sh

# 2. Authenticate
source venv/bin/activate
PYTHONPATH=src python -m childermass.gmail_mcp.auth --account=your@gmail.com

# 3. Enable in OpenCode (.opencode/opencode.json)
#    Set "enabled": true in the gmail section

# 4. Run tests
PYTHONPATH=src pytest src/childermass/gmail_mcp/tests/ -v
```

## Prerequisites

1. **Google Cloud Console**: Create a project, enable Gmail API
2. **OAuth2 Credentials**: Create "Desktop app" credentials
3. **Save credentials**: Download JSON to `~/.childermass/gmail-credentials.json`

## Architecture

```
src/childermass/gmail_mcp/
├── __init__.py      # Package metadata (v2.0.0)
├── auth.py          # OAuth2 + keyring token storage
├── client.py        # Gmail API wrapper + security validation
├── security.py      # Validators, rate limiter, audit logger
├── server.py        # FastMCP server (13 tools)
├── setup.sh         # One-command setup
├── requirements.txt # Dependencies
└── tests/
    └── test_security.py  # 92 tests
```

## Security Features

| Feature | Status | Description |
|---------|--------|-------------|
| Input validation | ✅ | All emails, paths, MIME types, queries validated |
| Token storage | ✅ | macOS Keychain with file fallback (chmod 600) |
| Rate limiting | ✅ | Token bucket: 10 sends/min, 60 reads/min |
| Audit logging | ✅ | JSON log at `~/.childermass/gmail-audit.log` |
| Error sanitization | ✅ | Bearer tokens, passwords, paths stripped |
| MIME blocking | ✅ | Executables, shell scripts blocked |
| Size limits | ✅ | 25 MB per attachment, 35 MB total |
| Header injection | ✅ | Newlines rejected in subject/email |

## CLI Commands

```bash
# Authenticate
python -m childermass.gmail_mcp.auth --account=user@gmail.com

# List accounts
python -m childermass.gmail_mcp.auth --list

# Migrate tokens to keyring
python -m childermass.gmail_mcp.auth --migrate-keyring

# Revoke account
python -m childermass.gmail_mcp.auth --revoke user@gmail.com

# Run server
python -m childermass.gmail_mcp.server
```

## Rate Limits

| Operation | Limit (per minute) |
|-----------|-------------------|
| send / forward / reply | 10 |
| draft | 20 |
| search / modify | 30 |
| list / read | 60 |
| download | 30 |
