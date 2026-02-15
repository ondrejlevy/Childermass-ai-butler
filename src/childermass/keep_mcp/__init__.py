"""
Childermass Google Keep MCP Server

Custom Google Keep integration with security hardening:
- Input validation on all operations
- Keyring-based token storage (with file fallback)
- Rate limiting per account/operation
- Audit logging to ~/.childermass/keep-audit.log
- Error message sanitization (no credential leaks)

Run with: python -m childermass.keep_mcp.server
"""

__version__ = "1.0.0"
