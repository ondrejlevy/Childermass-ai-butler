"""
Childermass Tracking MCP Server

Package tracking for Czech e-shops and carriers (Zásilkovna, Balíkovna,
PPL, DPD, GLS, Alza, Rohlik, Česká pošta).

Features:
- Automatic tracking info extraction from emails
- Web scraping of carrier tracking pages
- SQLite-based shipment database with status history
- Rate limiting, audit logging, error sanitization

Run with: python -m childermass.tracking_mcp.server
"""

__version__ = "1.0.0"
