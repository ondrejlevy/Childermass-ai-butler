# Childermass Tasks MCP Server

Custom Google Tasks MCP server for Claude Code / OpenCode.  
All data stays local – we only call official Google APIs.

## Features

- **17 MCP tools** for full Google Tasks management
- **Multi-account** OAuth2 support with keyring + file fallback
- **Security**: input validation, rate limiting, audit logging, error sanitization
- **Separate credentials** from Gmail and Calendar MCP servers

## Quick Start

```bash
# 1. Run setup
cd /Users/ondrej.levy/Agents/Home
./src/childermass/tasks_mcp/setup.sh

# 2. Authenticate
PYTHONPATH=src python3 -m childermass.tasks_mcp.auth --account=your@gmail.com

# 3. Run server (for testing)
PYTHONPATH=src python3 -m childermass.tasks_mcp.server
```

## Setup

### Prerequisites

1. **Google Cloud Project** with Google Tasks API enabled
2. **OAuth 2.0 credentials** (Desktop application type)
3. Python 3.11+

### OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Enable **Google Tasks API** (APIs & Services → Library)
4. Create OAuth 2.0 credentials:
   - APIs & Services → Credentials → Create Credentials → OAuth client ID
   - Application type: **Desktop app**
5. Download the JSON file and save to:

```
~/.childermass/tasks-credentials.json
```

> **Note:** This is separate from Gmail (`gmail-credentials.json`) and
> Calendar (`calendar-credentials.json`). You can use the same Google Cloud
> project but create separate OAuth client IDs, or reuse the same JSON
> if all APIs are enabled in the same project.

### Authentication

```bash
# Authenticate (opens browser for OAuth consent)
PYTHONPATH=src python3 -m childermass.tasks_mcp.auth --account=your@gmail.com

# Add more accounts
PYTHONPATH=src python3 -m childermass.tasks_mcp.auth --account=work@company.com

# List authenticated accounts
PYTHONPATH=src python3 -m childermass.tasks_mcp.auth --list
```

Tokens are stored securely:
- **macOS**: System Keychain (via keyring) under service `childermass-tasks-mcp`
- **Fallback**: `~/.childermass/tasks-tokens-{account}.json` (chmod 600)

## MCP Tools

### Task List Management
| Tool | Description |
|------|-------------|
| `tasks_list_tasklists` | List all task lists |
| `tasks_create_tasklist` | Create a new task list |
| `tasks_update_tasklist` | Rename a task list |
| `tasks_delete_tasklist` | Delete a task list and all its tasks |

### Task Operations
| Tool | Description |
|------|-------------|
| `tasks_list_tasks` | List tasks with filters (status, due date range) |
| `tasks_get_task` | Get full task details |
| `tasks_create_task` | Create a task (title, notes, due, parent) |
| `tasks_create_subtask` | Create a subtask under a parent task |
| `tasks_update_task` | Update task fields (atomic get+update) |
| `tasks_complete_task` | Mark a task as done |
| `tasks_uncomplete_task` | Reopen a completed task |
| `tasks_delete_task` | Permanently delete a task |
| `tasks_move_task` | Reorder or reparent a task |
| `tasks_clear_completed` | Remove all completed tasks from a list |
| `tasks_bulk_complete` | Complete multiple tasks at once |

### Convenience Tools (AI Assistant)
| Tool | Description |
|------|-------------|
| `tasks_list_all_tasks` | Aggregated view across all lists, sorted by due date |
| `tasks_list_due_today` | Tasks due today from all lists |
| `tasks_list_overdue` | Overdue tasks from all lists |
| `tasks_search` | Text search across all task lists |

## Security

### Input Validation
- Task list IDs and task IDs validated against injection
- Title max 1024 chars, notes max 8192 chars
- Status restricted to `needsAction` / `completed`
- Due dates validated and normalized to RFC3339

### Rate Limiting
Token bucket rate limiter per account:
- Read operations: 60/min
- Write operations: 30/min
- Delete/clear: 10/min
- Move: 20/min

### Audit Logging
All write operations logged to `~/.childermass/tasks-audit.log`:
- Create, update, delete, complete, uncomplete, move, clear

### Error Sanitization
All errors sanitized before returning to the LLM – OAuth tokens,
credentials paths, and internal details are never exposed.

## OpenCode Configuration

Add to `.opencode/opencode.json`:

```json
{
  "mcpServers": {
    "tasks": {
      "type": "stdio",
      "command": "/Users/ondrej.levy/Agents/Home/venv/bin/python",
      "args": ["-m", "childermass.tasks_mcp.server"],
      "env": {
        "PYTHONPATH": "/Users/ondrej.levy/Agents/Home/src"
      }
    }
  }
}
```

## Testing

```bash
# Run all tests
PYTHONPATH=src python3 -m pytest src/childermass/tasks_mcp/tests/ -v

# With coverage
PYTHONPATH=src python3 -m pytest src/childermass/tasks_mcp/tests/ -v --cov=childermass.tasks_mcp --cov-report=term-missing
```

## Architecture

```
tasks_mcp/
├── __init__.py        # Package metadata (v1.0.0)
├── server.py          # MCP tool definitions (17 tools)
├── client.py          # Google Tasks API wrapper
├── auth.py            # OAuth2 with keyring + file storage
├── security.py        # Validators, rate limiter, audit log
├── setup.sh           # Setup script
├── requirements.txt   # Dependencies
├── README.md          # This file
├── CHANGELOG.md       # Version history
└── tests/
    ├── __init__.py
    └── test_security.py  # ~95 test cases
```

## API Quotas

Google Tasks API: **50,000 queries/day** (per project).
The rate limiter ensures we stay well within this limit.
