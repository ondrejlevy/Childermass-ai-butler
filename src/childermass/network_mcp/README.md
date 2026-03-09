# Childermass UniFi Network MCP Server

Custom UniFi Network MCP server for OpenCode / Claude Code with integrated security hardening.
Connects locally to your UniFi console – all data stays on your LAN.

## Features

- **37 Network tools**: networks, firewall, vouchers, site health, clients, devices, traffic stats, DPI, IPS, rogue APs, alarms, events, WiFi/RF, combined security overview
- **Local-only access**: direct HTTPS to console on your LAN (no cloud dependency)
- **Full CRUD**: create, read, update, delete for networks, firewall rules, and vouchers
- **Security hardened** (v1.0):
  - Input validation on all operations (UUIDs, VLAN IDs, policy actions)
  - Keyring-based credential storage (macOS Keychain / Linux Secret Service)
  - Token bucket rate limiting per operation type
  - Structured JSON audit logging (`~/.childermass/network-audit.log`)
  - Error message sanitization (no IP addresses, credentials, or cookies leak to LLM)
  - Self-signed SSL handling with certificate verification option

## Quick Start

```bash
# 1. Setup
cd /Users/ondrej.levy/Agents/Home
./src/childermass/network_mcp/setup.sh

# 2. Configure console connection
source venv/bin/activate
PYTHONPATH=src python -m childermass.network_mcp.auth --setup

# 3. Test connectivity
PYTHONPATH=src python -m childermass.network_mcp.auth --test

# 4. Enable in OpenCode (.opencode/opencode.json)
#    Set "enabled": true in the network section

# 5. Run tests
PYTHONPATH=src pytest src/childermass/network_mcp/tests/ -v
```

## Prerequisites

1. **UniFi Console**: UDM, UDM Pro, UDM SE, Cloud Key Gen2+, etc.
2. **Local network access**: Console must be reachable from this machine
3. **Console credentials**: Local admin username and password
4. **Site ID**: UUID of the site to manage (discoverable via the UniFi web UI)

## Architecture

```
src/childermass/network_mcp/
├── __init__.py      # Package metadata (v2.0.0)
├── auth.py          # Console session management + keyring credential storage
├── client.py        # Integration API + Classic REST API wrappers
├── security.py      # Validators, rate limiter, audit logger
├── server.py        # FastMCP server (37 tools)
├── setup.sh         # One-command setup
├── requirements.txt # Dependencies
├── README.md        # This file
├── CHANGELOG.md     # Version history
└── tests/
    ├── __init__.py
    ├── test_security.py  # Security validation tests
    └── test_client.py    # Client function + parser tests
```

## Tools

### System Tools
| Tool | Description |
|------|-------------|
| `network_get_info` | Get application version information |
| `network_get_status` | Combined health overview: networks, firewall, vouchers, issues |

### Network Tools
| Tool | Description |
|------|-------------|
| `network_list_networks` | List all networks with VLAN, enabled status, DHCP guarding |
| `network_get_network` | Get details for a specific network |
| `network_create_network` | Create a new network (guest WiFi, IoT VLAN, etc.) |
| `network_update_network` | Update network name, VLAN, or enabled status |
| `network_delete_network` | Delete a network (with optional force) |

### Firewall Tools
| Tool | Description |
|------|-------------|
| `network_list_firewall_policies` | List all firewall policies with actions and zones |
| `network_get_firewall_policy` | Get details for a specific firewall policy |
| `network_create_firewall_policy` | Create a new firewall rule (ALLOW/DROP/REJECT) |
| `network_update_firewall_policy` | Update policy name, action, or enabled status |
| `network_delete_firewall_policy` | Delete a firewall policy |
| `network_list_firewall_zones` | List all firewall zones (Internal, External, DMZ, etc.) |

### Voucher Tools
| Tool | Description |
|------|-------------|
| `network_list_vouchers` | List hotspot vouchers with codes, limits, and usage |
| `network_get_voucher` | Get details for a specific voucher |
| `network_generate_vouchers` | Generate new guest access vouchers with time/data/speed limits |
| `network_delete_voucher` | Delete a voucher |

### Site Health & Status
| Tool | Description |
|------|-------------|
| `network_get_site_health` | Overall health: device counts, WAN IP, ISP, uptime, CPU/memory |

### Client Tools
| Tool | Description |
|------|-------------|
| `network_list_active_clients` | List all connected clients (name, IP, signal, traffic) |
| `network_get_client_details` | Get details for a specific client by MAC |
| `network_get_client_history` | Traffic history for a client (hourly buckets) |
| `network_block_client` | Block a client by MAC |
| `network_unblock_client` | Unblock a previously blocked client |
| `network_reconnect_client` | Force-reconnect (kick) a wireless client |

### Device Tools
| Tool | Description |
|------|-------------|
| `network_list_devices` | List all adopted APs, switches, gateways |
| `network_get_device_details` | Get details for a device by MAC |
| `network_restart_device` | Restart (reboot) a UniFi device |

### Traffic & DPI Tools
| Tool | Description |
|------|-------------|
| `network_get_site_stats` | Aggregated site traffic (hourly/daily/5min) |
| `network_get_dpi_stats` | Deep Packet Inspection stats by app or category |
| `network_get_client_dpi` | Per-client DPI (app usage breakdown) |

### Security Tools
| Tool | Description |
|------|-------------|
| `network_list_ips_events` | IPS intrusion alerts (with src/dst IP, action) |
| `network_list_rogue_aps` | Detected rogue / neighbouring access points |
| `network_list_alarms` | System alarms and notifications |
| `network_archive_alarm` | Archive (acknowledge) an alarm |
| `network_get_security_overview` | Combined security dashboard: IPS + rogues + alarms + blocked clients |

### Event & WiFi Tools
| Tool | Description |
|------|-------------|
| `network_list_events` | Controller event log (connections, changes, etc.) |
| `network_get_rf_environment` | RF channel utilisation (spectrum scan or rogue aggregation) |

## Security Features

| Feature | Status | Description |
|---------|--------|-------------|
| Input validation | ✅ | All IDs (UUID), VLAN IDs (1-4094), policy actions validated |
| Credential storage | ✅ | macOS Keychain with config file fallback (chmod 600) |
| Rate limiting | ✅ | Token bucket per operation (networks, firewall, clients, devices, stats, dpi, security, rf, write) |
| Audit logging | ✅ | JSON log at `~/.childermass/network-audit.log` |
| Error sanitization | ✅ | IP addresses, cookies, passwords, API keys, tokens stripped |
| Session management | ✅ | Auto re-login on 401, CSRF token handling |
| SSL handling | ✅ | Self-signed cert support with optional verification |

## CLI Commands

```bash
# Interactive console setup
python -m childermass.network_mcp.auth --setup

# Test console connectivity
python -m childermass.network_mcp.auth --test

# Show current configuration
python -m childermass.network_mcp.auth --show

# Delete all stored credentials
python -m childermass.network_mcp.auth --revoke
```

## API Reference

This server communicates with two UniFi local REST APIs:
- **Integration API v1**: `https://{CONSOLE_IP}/proxy/network/integration/v1/` – Network CRUD, firewall, vouchers
- **Classic REST API**: `https://{CONSOLE_IP}/proxy/network/api/s/{site}/` – Stats, clients, devices, DPI, IPS, alarms, events
- Auth: Cookie-based session with CSRF token
- Docs: https://developer.ui.com/network/v10.1.84/

### Key Endpoints Used
| Endpoint | Purpose |
|----------|---------|
| `POST /api/auth/login` | Authentication |
| `GET .../integration/v1/info` | Application version |
| `GET/POST/PUT/DELETE .../sites/{siteId}/networks` | Network CRUD |
| `GET/POST/PUT/DELETE .../sites/{siteId}/firewall/policies` | Firewall CRUD |
| `GET/PUT .../sites/{siteId}/firewall/policies/ordering` | Policy ordering |
| `GET/POST/PUT/DELETE .../sites/{siteId}/firewall/zones` | Zone CRUD |
| `GET/POST/DELETE .../sites/{siteId}/hotspot/vouchers` | Voucher management |
| `GET .../api/s/{site}/stat/health` | Site health |
| `GET .../api/s/{site}/stat/sta` | Active clients |
| `GET .../api/s/{site}/stat/device` | Devices |
| `POST .../api/s/{site}/stat/report/{period}.site` | Traffic stats |
| `GET .../api/s/{site}/stat/dpi` | DPI stats |
| `GET .../api/s/{site}/stat/ips/event` | IPS events |
| `GET .../api/s/{site}/stat/rogueap` | Rogue APs |
| `GET .../api/s/{site}/stat/alarm` | Alarms |
| `GET .../api/s/{site}/stat/event` | Events |
| `POST .../api/s/{site}/cmd/stamgr` | Client block/unblock/kick |
| `POST .../api/s/{site}/cmd/devmgr` | Device restart |
| `POST .../api/s/{site}/cmd/evtmgr` | Alarm archive |
