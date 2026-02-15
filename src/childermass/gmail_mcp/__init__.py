"""
Childermass Gmail MCP Server

Custom Gmail integration with security hardening:
- Input validation on all operations
- Keyring-based token storage (with file fallback)
- Rate limiting per account/operation
- Audit logging to ~/.childermass/gmail-audit.log
- Error message sanitization (no credential leaks)

Run with: python -m childermass.gmail_mcp.server
"""

__version__ = "2.0.0"
