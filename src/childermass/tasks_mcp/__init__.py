"""
Childermass Google Tasks MCP Server

Custom Google Tasks integration with security hardening:
- Input validation on all operations
- Keyring-based token storage (with file fallback)
- Rate limiting per account/operation
- Audit logging to ~/.childermass/tasks-audit.log
- Error message sanitization (no credential leaks)

Run with: python -m childermass.tasks_mcp.server
"""

__version__ = "1.0.0"
