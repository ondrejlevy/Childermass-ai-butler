# Childermass Contacts MCP Server

Custom Google Contacts MCP server for OpenCode / Claude Code with integrated security hardening.

## Features

- **15 Contacts tools**: search, list, get, find by email, find by org, birthday upcoming, my profile, create, update, delete, list groups, get group, create group, add/remove from group
- **Multi-account support**: authenticate multiple Google accounts
- **Security hardened**:
  - Input validation on all operations (names, emails, phones, resource names)
  - Keyring-based token storage (macOS Keychain / Linux Secret Service)
  - Token bucket rate limiting per operation type
  - Structured JSON audit logging (`~/.childermass/contacts-audit.log`)
  - Error message sanitization (no credential leaks to LLM)
  - Etag-based optimistic concurrency for updates

## Quick Start

```bash
# 1. Setup
cd /Users/ondrej.levy/Agents/Home
./src/childermass/contacts_mcp/setup.sh

# 2. Authenticate
source venv/bin/activate
PYTHONPATH=src python -m childermass.contacts_mcp.auth --account=your@gmail.com

# 3. Enable in OpenCode (.opencode/opencode.json)
#    Set "enabled": true in the contacts section

# 4. Run tests
PYTHONPATH=src pytest src/childermass/contacts_mcp/tests/ -v
```

## Prerequisites

1. **Google Cloud Console**: Create a project, enable People API
2. **OAuth2 Credentials**: Create "Desktop app" credentials
3. **Save credentials**: Download JSON to `~/.childermass/contacts-credentials.json`

## Architecture

```
src/childermass/contacts_mcp/
├── __init__.py      # Package metadata (v1.0.0)
├── auth.py          # OAuth2 + keyring token storage
├── client.py        # People API wrapper + security validation
├── security.py      # Validators, rate limiter, audit logger
├── server.py        # FastMCP server (15 tools)
├── setup.sh         # One-command setup
├── requirements.txt # Dependencies
└── tests/
    └── test_security.py  # Security test suite
```

## Tools

### Read Tools

| Tool | Description |
|------|-------------|
| `contacts_search` | Search contacts by name, email, phone, or organization |
| `contacts_list` | List all contacts with sorting options |
| `contacts_get` | Get full details of a specific contact |
| `contacts_find_by_email` | Find contacts by exact email address |
| `contacts_find_by_organization` | Find contacts by company name |
| `contacts_birthday_upcoming` | Find birthdays in the next N days |
| `contacts_get_my_profile` | Get authenticated user's profile |

### Write Tools

| Tool | Description |
|------|-------------|
| `contacts_create` | Create a new contact |
| `contacts_update` | Update an existing contact (requires etag) |
| `contacts_delete` | Delete a contact permanently |

### Group Tools

| Tool | Description |
|------|-------------|
| `contacts_list_groups` | List all contact groups/labels |
| `contacts_get_group` | Get details of a contact group |
| `contacts_create_group` | Create a new contact group |
| `contacts_add_to_group` | Add contacts to a group |
| `contacts_remove_from_group` | Remove contacts from a group |

## Security Features

| Feature | Status | Description |
|---------|--------|-------------|
| Input validation | ✅ | Names, emails, phones, URLs, resource names validated |
| Token storage | ✅ | macOS Keychain with file fallback (chmod 600) |
| Rate limiting | ✅ | Token bucket per operation type |
| Audit logging | ✅ | JSON log at `~/.childermass/contacts-audit.log` |
| Error sanitization | ✅ | Bearer tokens, passwords, paths stripped |
| Concurrency control | ✅ | Etag-based optimistic locking for updates |

## CLI Commands

```bash
# Authenticate
python -m childermass.contacts_mcp.auth --account=user@gmail.com

# List accounts
python -m childermass.contacts_mcp.auth --list

# Migrate tokens to keyring
python -m childermass.contacts_mcp.auth --migrate-keyring

# Revoke account
python -m childermass.contacts_mcp.auth --revoke user@gmail.com

# Run server
python -m childermass.contacts_mcp.server
```

## Rate Limits

| Operation | Limit (per minute) |
|-----------|-------------------|
| search | 30 |
| list / get | 60 |
| create / update | 20 |
| delete | 10 |
| group operations | 20–30 |
