# Changelog

## [1.0.0] - 2025-07-12

### Initial Release

#### Added
- **17 MCP tools** via FastMCP for Google Tasks API v1
  - `tasks_list_tasklists` – list all task lists
  - `tasks_create_tasklist` – create a new task list
  - `tasks_update_tasklist` – rename a task list
  - `tasks_delete_tasklist` – delete a task list and all its tasks
  - `tasks_list_tasks` – list tasks with filters (completed, due date range)
  - `tasks_get_task` – get full task details
  - `tasks_create_task` – create a task with title, notes, due date, parent
  - `tasks_create_subtask` – convenience: create a nested subtask
  - `tasks_update_task` – atomic get+update with field-level changes
  - `tasks_complete_task` – mark a task as done
  - `tasks_uncomplete_task` – reopen a completed task
  - `tasks_delete_task` – permanently delete a task
  - `tasks_move_task` – reorder or reparent tasks
  - `tasks_clear_completed` – clear all completed tasks from a list
  - `tasks_bulk_complete` – complete multiple tasks at once
  - `tasks_list_all_tasks` – aggregated view across all lists
  - `tasks_list_due_today` – convenience: today's tasks
  - `tasks_list_overdue` – convenience: overdue tasks
  - `tasks_search` – text search across all lists (client-side)
- **auth.py**: OAuth2 flow with keyring + file fallback, multi-account support
  - Separate credentials: `~/.childermass/tasks-credentials.json`
  - Separate tokens: `~/.childermass/tasks-tokens-{account}.json`
  - Separate keyring service: `childermass-tasks-mcp`
- **security.py**: Complete input validation module
  - Task list ID, task ID validation
  - Task title, notes length validation
  - Task status validation (`needsAction`, `completed`)
  - Due date format validation (date-only → RFC3339 conversion)
  - Search query validation
  - Max results validation (1-100)
  - Token bucket rate limiter per account/operation
  - Audit logging to `~/.childermass/tasks-audit.log`
  - Error message sanitization (prevents credential leaks)
- **client.py**: Full Google Tasks API v1 wrapper
  - All CRUD operations for task lists and tasks
  - Convenience methods: `list_all_tasks`, `list_due_today`, `list_overdue`, `search_tasks`, `bulk_complete`
  - Atomic get+update pattern for safe modifications
  - Module-level service cache
- **tests/test_security.py**: Comprehensive test suite (~95 test cases)
  - Validation, rate limiting, audit logging, and auth tests
