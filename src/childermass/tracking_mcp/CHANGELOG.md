# Changelog

## [1.0.0] - 2026-02-17

### Added
- Initial release of Tracking MCP server
- Support for Czech carriers: Zásilkovna, Balíkovna, PPL, DPD, GLS
- Support for Czech e-shops: Alza.cz tracking
- Generic fallback parser for unknown carriers
- SQLite database for shipment storage with status history
- Email parsing for automatic tracking info extraction
- Carrier auto-detection from URLs and email senders
- E-shop detection (Alza, Rohlik, Mall, CZC, Notino, Datart, Amazon, Temu)
- Batch status check for all active shipments
- Rate limiting, audit logging, error sanitization
- 8 MCP tools: register, status, check_all, get, list, archive, parse_email, detect_carrier
