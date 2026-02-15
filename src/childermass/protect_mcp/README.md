# Childermass UniFi Protect MCP Server

Custom UniFi Protect MCP server for OpenCode / Claude Code with integrated security hardening.
Connects locally to your NVR – all data stays on your LAN.

## Features

- **10 Protect tools**: cameras, snapshots, events, thumbnails, sensors, lights, doorbells, system status, activity summary
- **Local-only access**: direct HTTPS to NVR on your LAN (no cloud dependency)
- **Smart detection support**: person, vehicle, package, animal, face, license plate
- **Security hardened** (v1.0):
  - Input validation on all operations (IDs, timestamps, dimensions)
  - Keyring-based credential storage (macOS Keychain / Linux Secret Service)
  - Token bucket rate limiting per operation type
  - Structured JSON audit logging (`~/.childermass/protect-audit.log`)
  - Error message sanitization (no IP addresses, credentials, or cookies leak to LLM)
  - Self-signed SSL handling with certificate verification option

## Quick Start

```bash
# 1. Setup
cd /Users/ondrej.levy/Agents/Home
./src/childermass/protect_mcp/setup.sh

# 2. Configure NVR connection
source venv/bin/activate
PYTHONPATH=src python -m childermass.protect_mcp.auth --setup

# 3. Test connectivity
PYTHONPATH=src python -m childermass.protect_mcp.auth --test

# 4. Enable in OpenCode (.opencode/opencode.json)
#    Set "enabled": true in the protect section

# 5. Run tests
PYTHONPATH=src pytest src/childermass/protect_mcp/tests/ -v
```

## Prerequisites

1. **UniFi Protect NVR**: Cloud Key Gen2+, UDM, UDM Pro, UNVR, etc.
2. **Local network access**: NVR must be reachable from this machine
3. **NVR credentials**: Local admin username and password

## Architecture

```
src/childermass/protect_mcp/
├── __init__.py      # Package metadata (v1.0.0)
├── auth.py          # NVR session management + keyring credential storage
├── client.py        # Protect REST API wrapper + security validation
├── security.py      # Validators, rate limiter, audit logger
├── server.py        # FastMCP server (10 tools)
├── setup.sh         # One-command setup
├── requirements.txt # Dependencies
├── README.md        # This file
└── tests/
    ├── __init__.py
    └── test_security.py  # Security validation tests
```

## Tools

### Camera Tools
| Tool | Description |
|------|-------------|
| `protect_list_cameras` | List all cameras with status, recording state, smart detection capabilities |
| `protect_get_camera_snapshot` | Get live JPEG snapshot from a camera (base64) |

### Event Tools
| Tool | Description |
|------|-------------|
| `protect_list_events` | Query detected events with filters (time, camera, type, smart detection) |
| `protect_get_event_thumbnail` | Get thumbnail image for a specific event (base64 JPEG) |

### Sensor Tools
| Tool | Description |
|------|-------------|
| `protect_list_sensors` | List sensors with temperature, humidity, light, motion, door/window status |

### Light Tools
| Tool | Description |
|------|-------------|
| `protect_list_lights` | List Protect-managed lights (Floodlights) with status |
| `protect_toggle_light` | Turn a Protect light on or off |

### Doorbell Tools
| Tool | Description |
|------|-------------|
| `protect_check_doorbell` | Check doorbell status – last ring, LCD message, capabilities |

### System Tools
| Tool | Description |
|------|-------------|
| `protect_get_system_status` | Complete system health: NVR, cameras, sensors, lights, issues |
| `protect_get_recent_activity` | Activity summary: event counts, smart detection breakdown, per-camera stats |

## Security Features

| Feature | Status | Description |
|---------|--------|-------------|
| Input validation | ✅ | All IDs (24-char hex), timestamps, dimensions validated |
| Credential storage | ✅ | macOS Keychain with config file fallback (chmod 600) |
| Rate limiting | ✅ | Token bucket: 10 snapshots/min, 30 events/min, 5 bootstrap/min |
| Audit logging | ✅ | JSON log at `~/.childermass/protect-audit.log` |
| Error sanitization | ✅ | IP addresses, cookies, passwords, tokens stripped |
| Session management | ✅ | Auto re-login on 401, CSRF token handling |
| SSL handling | ✅ | Self-signed cert support with optional verification |

## CLI Commands

```bash
# Interactive NVR setup
python -m childermass.protect_mcp.auth --setup

# Test NVR connectivity
python -m childermass.protect_mcp.auth --test

# Show current configuration
python -m childermass.protect_mcp.auth --show

# Delete all stored credentials
python -m childermass.protect_mcp.auth --revoke
```

## API Reference

This server communicates with the UniFi Protect local REST API:
- Base URL: `https://{NVR_IP}/proxy/protect/api/`
- Auth: Cookie-based session with CSRF token
- Docs: https://developer.ui.com/protect/v6.2.88/

### Key Endpoints Used
| Endpoint | Purpose |
|----------|---------|
| `POST /api/auth/login` | Authentication |
| `GET /proxy/protect/api/bootstrap` | Complete system state |
| `GET /proxy/protect/api/cameras/{id}/snapshot` | Camera snapshots |
| `GET /proxy/protect/api/events` | Event history |
| `GET /proxy/protect/api/events/{id}/thumbnail` | Event thumbnails |
| `PATCH /proxy/protect/api/lights/{id}` | Light control |
