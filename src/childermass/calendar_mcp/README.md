# Childermass Calendar MCP Server

Custom Google Calendar MCP server for OpenCode / Claude Code with integrated security hardening.

## Features

- **14 Calendar tools**: list calendars, list/search/create/update/delete events, quick-add, move, recurring instances, free/busy, today/week agenda
- **Multi-account support**: authenticate multiple Google accounts
- **ETag-based updates**: atomic get+update with conflict detection
- **Google Meet**: optional conferencing link on event creation
- **Security hardened**:
  - Input validation on all operations (calendar ID, event ID, datetime, timezone, email, recurrence)
  - Keyring-based token storage (macOS Keychain / Linux Secret Service)
  - Token bucket rate limiting per account/operation
  - Structured JSON audit logging (`~/.childermass/calendar-audit.log`)
  - Error message sanitization (no credential leaks to LLM)

## Quick Start

```bash
# 1. Setup
cd /Users/ondrej.levy/Agents/Home
./src/childermass/calendar_mcp/setup.sh

# 2. Authenticate
source venv/bin/activate
PYTHONPATH=src python -m childermass.calendar_mcp.auth --account=your@gmail.com

# 3. Enable in OpenCode (.opencode/opencode.json)
#    Set "enabled": true in the calendar section

# 4. Run tests
PYTHONPATH=src pytest src/childermass/calendar_mcp/tests/ -v
```

## Prerequisites

1. **Google Cloud Console**: Create a project, enable Google Calendar API
2. **OAuth2 Credentials**: Create "Desktop app" credentials
3. **Save credentials**: Download JSON to `~/.childermass/calendar-credentials.json`

## Architecture

```
src/childermass/calendar_mcp/
├── __init__.py      # Package metadata (v1.0.0)
├── auth.py          # OAuth2 + keyring token storage
├── client.py        # Calendar API wrapper + security validation
├── security.py      # Validators, rate limiter, audit logger
├── server.py        # FastMCP server (14 tools)
├── setup.sh         # One-command setup
├── requirements.txt # Dependencies
└── tests/
    └── test_security.py  # Security / validation tests
```

## Tools

| # | Tool | Description |
|---|------|-------------|
| 1 | `calendar_list_calendars` | List all calendars for account |
| 2 | `calendar_list_events` | List events from a specific calendar |
| 3 | `calendar_list_all_events` | List events from all calendars |
| 4 | `calendar_get_event` | Get detailed event info (with ETag) |
| 5 | `calendar_search_events` | Full-text search across events |
| 6 | `calendar_create_event` | Create new event (with optional Google Meet) |
| 7 | `calendar_update_event` | Update event (get+update with ETag) |
| 8 | `calendar_delete_event` | Delete event with attendee notification control |
| 9 | `calendar_quick_add` | Natural language event creation |
| 10 | `calendar_move_event` | Move event between calendars |
| 11 | `calendar_check_availability` | Check free/busy status |
| 12 | `calendar_list_recurring` | List instances of recurring event |
| 13 | `calendar_get_today_agenda` | Today's agenda (convenience) |
| 14 | `calendar_get_week_agenda` | This week's agenda (convenience) |

## Security Features

| Feature | Status | Description |
|---------|--------|-------------|
| Input validation | ✅ | Calendar IDs, event IDs, datetimes, emails, recurrence rules validated |
| Token storage | ✅ | macOS Keychain with file fallback (chmod 600) |
| Rate limiting | ✅ | Token bucket: 20 writes/min, 60 reads/min |
| Audit logging | ✅ | JSON log at `~/.childermass/calendar-audit.log` |
| Error sanitization | ✅ | Bearer tokens, passwords, paths stripped |
| ETag conflicts | ✅ | Atomic updates prevent silent overwrites |

## CLI Commands

```bash
# Authenticate
python -m childermass.calendar_mcp.auth --account=user@gmail.com

# List accounts
python -m childermass.calendar_mcp.auth --list

# Migrate tokens to keyring
python -m childermass.calendar_mcp.auth --migrate-keyring

# Revoke account
python -m childermass.calendar_mcp.auth --revoke user@gmail.com

# Run server
python -m childermass.calendar_mcp.server
```

## Rate Limits

| Operation | Limit (per minute) |
|-----------|-------------------|
| list events / calendars | 60 |
| free/busy | 30 |
| create / update / delete / move | 20 |

## Credentials Separation

This server uses **separate** credentials from the Gmail MCP server:

| | Gmail MCP | Calendar MCP |
|--|-----------|--------------|
| Credentials | `~/.childermass/gmail-credentials.json` | `~/.childermass/calendar-credentials.json` |
| Tokens | `~/.childermass/gmail-tokens-{account}.json` | `~/.childermass/calendar-tokens-{account}.json` |
| Keyring service | `childermass-gmail-mcp` | `childermass-calendar-mcp` |
| Audit log | `~/.childermass/gmail-audit.log` | `~/.childermass/calendar-audit.log` |
| OAuth scopes | `gmail.modify`, `gmail.readonly` | `calendar`, `calendar.readonly` |
