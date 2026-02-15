# Changelog

## [1.0.0] - 2026-02-13

### Initial Release

#### Added
- **28 MCP tools** for Google Keep integration:
  - Note CRUD: create, get, list, search, update, delete
  - List items: add, update, check, uncheck, delete, sort, get unchecked, bulk check
  - Sharing: share, unshare, list collaborators
  - Labels: list, create, delete, add to note, remove from note
  - Quick actions: pin, unpin, archive, unarchive, set color
  - Shortcuts: create shopping list, duplicate note
- **security.py**: Input validation module
  - Note title/text/item validation with length limits
  - Note ID and item ID format validation
  - Color and note type whitelist validation
  - Label name validation
  - Email validation for collaborator operations
  - Query string sanitization
  - Error message sanitization (credential leak prevention)
- **Rate limiter**: Token bucket algorithm, per-account per-operation
- **Audit logger**: Structured JSON logging to `~/.childermass/keep-audit.log`
- **Keyring integration**: macOS Keychain / Linux Secret Service token storage
- **State caching**: Keep state cached for faster startup
- **auth.py**: Master token authentication via gpsoauth
  - Interactive authentication flow
  - Multi-account support
  - Token migration to keyring
  - Account listing and revocation

#### Architecture
- Built on `gkeepapi` (unofficial Google Keep API client)
- Same structure as `gmail_mcp` / `calendar_mcp`
- FastMCP server framework
