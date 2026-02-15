"""
Childermass Google Contacts MCP Server

Custom Google Contacts (People API) integration with security hardening:
- Input validation on all operations
- Keyring-based token storage (with file fallback)
- Rate limiting per account/operation
- Audit logging to ~/.childermass/contacts-audit.log
- Error message sanitization (no credential leaks)

Run with: python -m childermass.contacts_mcp.server
"""

__version__ = "1.0.0"
