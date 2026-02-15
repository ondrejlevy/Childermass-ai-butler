# Changelog

## [1.0.0] – 2026-02-13

### Added
- Initial release of Childermass UniFi Network MCP Server
- **17 tools** covering networks, firewall policies, firewall zones, and hotspot vouchers
- Local-only access via direct HTTPS to UniFi console on LAN
- Full CRUD operations for networks, firewall policies, and firewall zones
- Voucher generation and management for guest network access
- Combined system status overview for quick health checks
- Security hardening:
  - UUID validation for all resource IDs
  - VLAN ID range validation (1-4094)
  - Firewall policy action validation (ALLOW, DROP, REJECT)
  - Voucher parameter bounds checking
  - Filter expression sanitization
  - Console address injection prevention
  - Token bucket rate limiting per operation type
  - Structured JSON audit logging (`~/.childermass/network-audit.log`)
  - Error message sanitization (IP, credentials, cookies, API keys stripped)
  - Keyring-based credential storage with file fallback
  - CSRF token session management with auto re-login on 401
  - Self-signed SSL certificate handling
- CLI tools for setup, connectivity testing, config display, and credential revocation
- Comprehensive test suite for security layer
