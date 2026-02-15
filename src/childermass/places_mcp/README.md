# Childermass Places MCP Server

Custom Google Places API (New) MCP server for Claude Code / OpenCode.

Provides tools for searching places, getting business details, finding nearby services, and more — all through the [Google Places API (New)](https://developers.google.com/maps/documentation/places/web-service/op-overview) v1.

## Features

- **Text Search** – find places by natural language query
- **Nearby Search** – discover places around a geographic point
- **Place Details** – get address, phone, hours, reviews, photos, attributes
- **Autocomplete** – interactive place suggestions as you type
- **Photo URIs** – retrieve place photo URLs
- **Smart Home / PA tools** – find nearby services, restaurants, EV chargers

### Security

- OAuth 2.0 with secure token storage (system keyring + file fallback)
- Input validation on every parameter
- Per-account / per-operation rate limiting
- JSON audit logging (`~/.childermass/places-audit.log`)
- Error message sanitization – credentials never leak to the LLM

## Quick Start

### 1. Setup

```bash
cd /Users/ondrej.levy/Agents/Home
./src/childermass/places_mcp/setup.sh
```

### 2. Enable Places API

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create / select a project
3. Enable **Places API (New)** under APIs & Services
4. Create **OAuth 2.0 credentials** (Desktop app type)
5. Download the JSON → `~/.childermass/places-credentials.json`

### 3. Authenticate

```bash
PYTHONPATH=src python -m childermass.places_mcp.auth --account=you@gmail.com
```

### 4. Run

```bash
PYTHONPATH=src python -m childermass.places_mcp.server
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `places_text_search` | Search places by text query |
| `places_nearby_search` | Search places near lat/lng |
| `places_search_with_filters` | Search with price/rating/open filters |
| `places_get_details` | Full details for a place ID |
| `places_get_opening_hours` | Opening hours for a place |
| `places_get_reviews` | User reviews for a place |
| `places_autocomplete` | Autocomplete suggestions |
| `places_get_photo` | Get photo URI from resource name |
| `places_find_nearby_service` | Find plumbers, electricians, etc. |
| `places_find_restaurants` | Find restaurants with cuisine/price filters |
| `places_find_ev_chargers` | Find EV charging stations |

## Configuration

| Path | Description |
|------|-------------|
| `~/.childermass/places-credentials.json` | OAuth 2.0 client credentials |
| `~/.childermass/places-tokens-{account}.json` | Token fallback (when keyring unavailable) |
| `~/.childermass/places-audit.log` | Audit log (JSON lines) |

Tokens are stored in the system keyring under service `childermass-places-mcp` when available.

## Testing

```bash
PYTHONPATH=src pytest src/childermass/places_mcp/tests/ -v
```

## Architecture

```
places_mcp/
├── __init__.py          # Package metadata
├── auth.py              # OAuth 2.0 authentication & token management
├── security.py          # Validators, rate limiter, audit, sanitizer
├── client.py            # Places API (New) REST client wrapper
├── server.py            # FastMCP server with tool definitions
├── requirements.txt     # Python dependencies
├── setup.sh             # One-command setup script
├── README.md            # This file
├── CHANGELOG.md         # Version history
└── tests/
    ├── __init__.py
    └── test_security.py # Security layer tests
```

## API Notes

The Places API (New) is a **REST API** (not discovery-based like Gmail/Calendar APIs). Authentication uses OAuth 2.0 with the `cloud-platform` scope, and requests are made via `google.auth.transport.requests.AuthorizedSession`. Field selection is controlled via the `X-Goog-FieldMask` header, which directly impacts billing.
