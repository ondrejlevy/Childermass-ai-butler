# Changelog

## [1.0.0] - 2025-07-11

### Initial Release

#### Added
- **14 MCP tools** via FastMCP for Google Calendar API v3
  - `calendar_list_calendars` – list all calendars
  - `calendar_list_events` – list events with optional time range
  - `calendar_list_all_events` – list events across all calendars
  - `calendar_get_event` – get event details with ETag
  - `calendar_search_events` – full-text search
  - `calendar_create_event` – create with attendees, recurrence, Google Meet
  - `calendar_update_event` – atomic get+update with ETag conflict detection
  - `calendar_delete_event` – delete with attendee notification control
  - `calendar_quick_add` – natural language event creation
  - `calendar_move_event` – move events between calendars
  - `calendar_check_availability` – free/busy query
  - `calendar_list_recurring` – list recurring event instances
  - `calendar_get_today_agenda` – convenience: today's events
  - `calendar_get_week_agenda` – convenience: this week's events
- **auth.py**: OAuth2 flow with keyring + file fallback, multi-account support
- **security.py**: Complete input validation module
  - Calendar ID, event ID validation
  - DateTime / timezone format validation
  - Recurrence rule validation (RRULE/EXDATE/RDATE)
  - Attendee email validation
  - Event summary, description, location length checks
  - Color ID validation (1-11)
  - Search query sanitization
  - sendUpdates parameter validation
  - Quick-add text validation
  - Error message sanitization (credential leak prevention)
- **Rate limiter**: Token bucket algorithm, per-account per-operation
- **Audit logger**: Structured JSON logging to `~/.childermass/calendar-audit.log`
- **Keyring integration**: macOS Keychain / Linux Secret Service token storage
- **Token migration**: `--migrate-keyring` CLI command
- **Account revocation**: `--revoke` CLI command
- **Test suite**: Security validation tests
- **Setup script**: One-command setup with validation
- **Separate credentials**: Independent from Gmail MCP (own credentials.json, tokens, keyring service)
