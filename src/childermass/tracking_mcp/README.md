# Childermass Tracking MCP Server

Package tracking for Czech e-shops and carriers. Monitors shipment status
by scraping public tracking pages and provides a unified interface for
querying delivery status.

## Supported Carriers

| Carrier | Tracking URL Pattern | Status |
|---------|---------------------|--------|
| Zásilkovna (Packeta) | `tracking.zasilkovna.cz/*` | ✓ |
| Balíkovna (Česká pošta) | `b2c.cpost.cz/*`, `postaonline.cz/*` | ✓ |
| PPL CZ | `ppl.cz/vyhledat-zasilku*` | ✓ |
| DPD CZ | `tracking.dpd.de/*`, `dpd.cz/*` | ✓ |
| GLS CZ | `gls-group.com/CZ/*` | ✓ |
| Alza.cz | `alza.cz/Order/Track/*` | ✓ |
| Generic | Any URL (fallback) | ✓ |

## Tools

| Tool | Description |
|------|-------------|
| `tracking_register` | Register a new shipment for tracking |
| `tracking_status` | Check live status (scrapes tracking page) |
| `tracking_check_all` | Batch check all active shipments |
| `tracking_get` | Get shipment details from DB (no scrape) |
| `tracking_list` | List shipments with filters |
| `tracking_archive` | Mark shipment as inactive |
| `tracking_parse_email` | Parse tracking info from email content |
| `tracking_detect_carrier` | Detect carrier from URL or email sender |

## Workflow

1. **Email arrives** with shipment notification
2. Agent reads email via `gmail_read_email`
3. Agent calls `tracking_parse_email` with email body/HTML
4. Agent calls `tracking_register` with parsed data
5. Periodically (e.g., morning briefing), agent calls `tracking_check_all`
6. User can ask about specific shipment via `tracking_status` or `tracking_get`

## Setup

```bash
cd /Users/ondrej.levy/Agents/Home
./src/childermass/tracking_mcp/setup.sh
```

## Configuration

No API keys required. The server scrapes public tracking pages.

Data is stored in `~/.childermass/tracking/tracking.sqlite`.

## Running

```bash
python -m childermass.tracking_mcp.server
```

## Testing

```bash
PYTHONPATH=src pytest src/childermass/tracking_mcp/tests/ -v
```
