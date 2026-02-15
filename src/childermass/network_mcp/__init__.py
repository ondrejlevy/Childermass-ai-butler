"""
Childermass UniFi Network MCP Server

Custom UniFi Network integration with security hardening:
- Input validation on all operations
- Keyring-based credential storage (with file fallback)
- Rate limiting per operation
- Structured JSON audit logging (~/.childermass/network-audit.log)
- Error message sanitization (no credential leaks to LLM)

Run with: python -m childermass.network_mcp.server
"""

__version__ = "1.0.0"
