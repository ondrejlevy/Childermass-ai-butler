# Childermass Mapy.com MCP Server

MCP (Model Context Protocol) server providing AI agents with access to the [Mapy.com REST API](https://developer.mapy.com/) for geocoding, route planning, elevation, and timezone services.

## Features

### MCP Tools (9 tools)

#### Geocoding & Places
| Tool | Description |
|------|-------------|
| `mapy_search_places` | Search for places, addresses, POIs by text query (forward geocoding) |
| `mapy_suggest_places` | Autocomplete/suggest places while typing (handles typos) |
| `mapy_reverse_geocode` | Get address info for given coordinates |

#### Route Planning & Navigation
| Tool | Description |
|------|-------------|
| `mapy_plan_route` | Plan route between 2+ points with full details |
| `mapy_travel_time` | Get travel time and distance (simplified routing) |
| `mapy_compare_routes` | Compare transport modes (car vs foot vs bike) |
| `mapy_find_nearest` | Find nearest destination from a list (matrix routing) |

#### Elevation & Timezone
| Tool | Description |
|------|-------------|
| `mapy_get_elevation` | Get elevation in meters for positions |
| `mapy_get_timezone` | Get timezone, local time, UTC offset for location |

### Smart Home & Personal Assistant Use Cases

- **Commute planning**: "How long will it take to drive to work?" → `mapy_travel_time`
- **Transport comparison**: "Should I drive or take the bus?" → `mapy_compare_routes`
- **Nearest services**: "Which pharmacy is closest?" → `mapy_find_nearest`
- **Address validation**: "Is this a valid address?" → `mapy_search_places`
- **Route with departure time**: "When should I leave to arrive by 9 AM?" → `mapy_plan_route`
- **Location lookup**: "Find restaurants near home" → `mapy_suggest_places` with `prefer_near`
- **Reverse lookup**: "What's at these coordinates?" → `mapy_reverse_geocode`
- **Elevation check**: "What's the altitude at the cabin?" → `mapy_get_elevation`
- **Timezone info**: "What time is it in New York?" → `mapy_get_timezone`

### Supported Route Types

| Type | Description |
|------|-------------|
| `car_fast` | Fast car route (default) |
| `car_fast_traffic` | Fast car route with traffic (CZ only) |
| `car_short` | Short car route |
| `foot_fast` | Fast walking route |
| `foot_hiking` | Walking with hiking trail preference |
| `bike_road` | Road bicycle |
| `bike_mountain` | Mountain bike |

### Security Features

| Feature | Description |
|---------|-------------|
| Input validation | All parameters validated before API calls |
| Rate limiting | Token bucket algorithm per-operation |
| Error sanitization | API keys scrubbed from error messages |
| Audit logging | JSON log to `~/.childermass/mapy-audit.log` |
| Secure key storage | System keyring (macOS Keychain) with file fallback |

## Setup

### 1. Get API Key

1. Go to [developer.mapy.com/account](https://developer.mapy.com/account/)
2. Log in with your Seznam account
3. Create an API project
4. Copy the generated API key

### 2. Run Setup Script

```bash
cd /path/to/Agents/Home
./src/childermass/mapy_mcp/setup.sh
```

### 3. Configure API Key (if not done during setup)

```bash
PYTHONPATH=src python3 -m childermass.mapy_mcp.auth --set-api-key YOUR_KEY
```

### 4. Verify Configuration

```bash
PYTHONPATH=src python3 -m childermass.mapy_mcp.auth --verify
```

## MCP Client Configuration

```json
{
  "mcpServers": {
    "mapy": {
      "command": "/path/to/venv/bin/python",
      "args": ["-m", "childermass.mapy_mcp.server"],
      "env": {
        "PYTHONPATH": "/path/to/Agents/Home/src"
      }
    }
  }
}
```

## CLI Commands

```bash
# Store API key
python -m childermass.mapy_mcp.auth --set-api-key YOUR_KEY

# Verify API key
python -m childermass.mapy_mcp.auth --verify

# Remove API key
python -m childermass.mapy_mcp.auth --delete
```

## Rate Limits

| Operation | Limit |
|-----------|-------|
| Geocode / Suggest / Reverse geocode | 60/min |
| Route planning | 30/min |
| Matrix routing | 20/min |
| Elevation | 40/min |
| Timezone | 40/min |

## Architecture

```
mapy_mcp/
├── __init__.py          # Package metadata
├── auth.py              # API key management (keyring + file)
├── security.py          # Validation, rate limiting, audit logging
├── client.py            # Mapy.com REST API wrapper
├── server.py            # MCP tools (FastMCP)
├── requirements.txt     # Dependencies
├── setup.sh             # Automated setup script
├── README.md            # This file
├── CHANGELOG.md         # Version history
└── tests/
    ├── __init__.py
    └── test_security.py # Comprehensive security tests
```

## Running Tests

```bash
PYTHONPATH=src pytest src/childermass/mapy_mcp/tests/ -v
```

## API Reference

- [Mapy.com REST API documentation](https://developer.mapy.com/cs/rest-api/)
- [Technical docs](https://api.mapy.com/v1/docs/)
- [Common principles](https://api.mapy.com/v1/docs/commons/)
