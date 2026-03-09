# Changelog

## [2.0.0] – 2026-02-17

### Added
- **20 new MCP tools** (37 total) covering classic UniFi REST API:
  - **Site Health**: `network_get_site_health` – overall system health, device counts, WAN/ISP info, CPU/memory
  - **Active Clients**: `network_list_active_clients`, `network_get_client_details`, `network_get_client_history`, `network_block_client`, `network_unblock_client`, `network_reconnect_client`
  - **Devices**: `network_list_devices`, `network_get_device_details`, `network_restart_device`
  - **Traffic Stats**: `network_get_site_stats` (hourly/daily/5min aggregation)
  - **DPI**: `network_get_dpi_stats`, `network_get_client_dpi` (deep packet inspection by app/category)
  - **Security**: `network_list_ips_events`, `network_list_rogue_aps`, `network_list_alarms`, `network_archive_alarm`, `network_get_security_overview`
  - **Events**: `network_list_events` (controller event log)
  - **WiFi/RF**: `network_get_rf_environment` (channel utilisation with spectrum scan fallback)
- 12 new data classes: `HealthStatus`, `ActiveClient`, `DeviceInfo`, `SiteStats`, `DpiStat`, `IpsEvent`, `RogueAp`, `Alarm`, `RfChannel`, `Event`
- Classic API prefix `_CLASSIC_PREFIX` and `_resolve_site_name()` helper
- 6 new input validators: `validate_mac_address`, `validate_period`, `validate_timestamp_ms`, `validate_dpi_type`, `validate_history_hours`, `validate_event_limit`
- 6 new rate limiter categories: stats (30/min), dpi (20/min), security (30/min), clients (30/min), devices (30/min), rf (20/min)
- Combined `get_security_overview()` tool for AI assistant: IPS + rogue APs + alarms + blocked clients in one call
- Comprehensive test suite: `test_client.py` (parser + mocked HTTP tests), extended `test_security.py` (new validator + rate limiter tests)

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
