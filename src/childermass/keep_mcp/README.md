# Childermass Google Keep MCP Server

Custom Google Keep MCP server for OpenCode / Claude Code with integrated security hardening.

## Features

- **28 Keep tools**: notes CRUD, list items, sharing, labels, quick actions, shortcuts
- **Multi-account support**: authenticate multiple Google accounts
- **Security hardened**:
  - Input validation on all operations (title, text, IDs, email, colors)
  - Keyring-based token storage (macOS Keychain / Linux Secret Service)
  - Token bucket rate limiting per account/operation
  - Structured JSON audit logging (`~/.childermass/keep-audit.log`)
  - Error message sanitization (no credential leaks to LLM)

## Quick Start

```bash
# 1. Setup
cd /Users/ondrej.levy/Agents/Home
./src/childermass/keep_mcp/setup.sh

# 2. Authenticate
source venv/bin/activate
PYTHONPATH=src python -m childermass.keep_mcp.auth --account=your@gmail.com

# 3. Enable in OpenCode (.opencode/opencode.json)
#    Set "enabled": true in the keep section

# 4. Run tests
PYTHONPATH=src pytest src/childermass/keep_mcp/tests/ -v
```

## Prerequisites

1. **Master Token**: gkeepapi uses a master token for authentication
2. **gpsoauth**: Used to obtain master token from Google account

### Obtaining a Master Token

Option 1 – Using gpsoauth directly:
```python
import gpsoauth
token = gpsoauth.exchange_token('your@gmail.com', '<oauth_token>', '<android_id>')
```

Option 2 – Using Docker:
```bash
docker run --rm -it --entrypoint /bin/sh python:3 -c \
  'pip install gpsoauth; python3 -c '\''print(__import__("gpsoauth").exchange_token(input("Email: "), input("OAuth Token: "), input("Android ID: ")))'\'''
```

See [gpsoauth documentation](https://github.com/simon-weber/gpsoauth#alternative-flow) for detailed instructions.

## Architecture

```
src/childermass/keep_mcp/
├── __init__.py      # Package metadata (v1.0.0)
├── auth.py          # Master token auth + keyring storage + state caching
├── client.py        # gkeepapi wrapper + security validation
├── security.py      # Validators, rate limiter, audit logger
├── server.py        # FastMCP server (28 tools)
├── requirements.txt # Dependencies
├── setup.sh         # One-command setup
├── README.md        # This file
├── CHANGELOG.md     # Version history
└── tests/
    ├── __init__.py
    └── test_security.py
```

## Tools Reference

### Note CRUD
| Tool | Description |
|------|-------------|
| `keep_create_note` | Create text note or checklist |
| `keep_list_notes` | List notes with filtering (query, pinned, archived, labels, colors) |
| `keep_get_note` | Get full note details |
| `keep_search_notes` | Search notes by text |
| `keep_update_note` | Update note title, text, color, pin, archive |
| `keep_delete_note` | Delete (trash) a note |

### List Items
| Tool | Description |
|------|-------------|
| `keep_list_items` | Get all items in a list |
| `keep_add_list_item` | Add item to list |
| `keep_update_list_item` | Update item text or checked state |
| `keep_check_item` | Mark item as done |
| `keep_uncheck_item` | Mark item as not done |
| `keep_delete_list_item` | Delete item from list |
| `keep_sort_list` | Sort items alphabetically |
| `keep_get_unchecked_items` | Get remaining (unchecked) items |
| `keep_bulk_check_items` | Bulk check/uncheck multiple items |

### Sharing
| Tool | Description |
|------|-------------|
| `keep_share_note` | Share note with collaborator |
| `keep_unshare_note` | Remove collaborator |
| `keep_list_collaborators` | List all collaborators |

### Labels
| Tool | Description |
|------|-------------|
| `keep_list_labels` | List all labels |
| `keep_create_label` | Create a label |
| `keep_delete_label` | Delete a label |
| `keep_add_label` | Add label to note |
| `keep_remove_label` | Remove label from note |

### Quick Actions
| Tool | Description |
|------|-------------|
| `keep_pin_note` | Pin note to top |
| `keep_unpin_note` | Unpin note |
| `keep_archive_note` | Archive note |
| `keep_unarchive_note` | Unarchive note |
| `keep_set_color` | Set note color with semantic coding |
| `keep_create_shopping_list` | Quick-create pinned shopping list |
| `keep_duplicate_note` | Duplicate note (templates) |

## Security

### Input Validation
- Note titles: max 1,000 chars, no control characters
- Note text: max 20,000 chars
- List items: max 1,000 chars per item, max 1,000 items per list
- Note/item IDs: alphanumeric format validation
- Colors: whitelist validation
- Emails: format validation with injection prevention

### Rate Limiting
- Create/update/delete: 20/min
- Share/unshare: 10/min
- List/get/search: 60/min
- Check/uncheck/add/delete items: 30/min
- Label operations: 20/min

### Audit Logging
All write operations logged to `~/.childermass/keep-audit.log` as structured JSON.

### Error Sanitization
Master tokens, OAuth tokens, and file paths are automatically scrubbed from error messages before they reach the LLM.
