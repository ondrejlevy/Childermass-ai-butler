"""
Childermass UniFi Protect MCP Server

Custom UniFi Protect integration with security hardening:
- Input validation on all operations
- Keyring-based credential storage (with file fallback)
- Rate limiting per operation
- Structured JSON audit logging (~/.childermass/protect-audit.log)
- Error message sanitization (no credential leaks to LLM)

Run with: python -m childermass.protect_mcp.server
"""

__version__ = "1.0.0"
