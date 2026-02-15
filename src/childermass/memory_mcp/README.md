# Childermass Memory MCP Server

Persistent cognitive memory for the Childermass AI butler. Built on [OpenMemory](https://github.com/CaviraOSS/OpenMemory) Python SDK with local SQLite storage.

## Features

- **Semantic Memory Storage** — Store and recall preferences, routines, facts, feedback, and patterns with cognitive sector classification (episodic, semantic, procedural, emotional, reflective)
- **Temporal Knowledge Graph** — Track how facts change over time with full history (e.g., preferred bedroom temperature changed from 21°C to 22°C on July 1st)
- **Semantic Search** — Find relevant memories by meaning, not just keywords
- **Security** — Input validation, rate limiting, error sanitization, audit logging
- **Zero Config** — Synthetic embeddings (no external API needed), local SQLite DB

## Architecture

```
memory_mcp/
├── server.py         # FastMCP tool definitions (10 tools)
├── client.py         # MemoryClient wrapping OpenMemory SDK
├── auth.py           # Configuration management
├── security.py       # Validators, rate limiter, sanitization
├── data/
│   └── memory.sqlite # Local database (auto-created)
└── tests/
    └── test_security.py
```

## Tools

### Memory Operations

| Tool | Description |
|------|-------------|
| `memory_store` | Store a memory (preference, routine, fact, feedback, pattern) |
| `memory_recall` | Search memories by semantic similarity |
| `memory_recall_by_sector` | Get memories from a specific cognitive sector |
| `memory_get` | Get a specific memory by ID |
| `memory_list` | List memories, optionally filtered by category |
| `memory_forget` | Delete a specific memory |

### Temporal Knowledge Graph

| Tool | Description |
|------|-------------|
| `memory_store_fact` | Store a temporal fact (subject-predicate-object with date) |
| `memory_update_fact` | Update a fact, preserving history |
| `memory_timeline` | Get chronological history of an entity |
| `memory_summary` | Memory system statistics and overview |

## Categories

Childermass organizes memories by purpose:

- **preference** — User likes/dislikes, comfort settings
- **routine** — Regular schedules and habits
- **fact** — Objective information about the household
- **feedback** — User corrections and preferences about assistant behavior
- **pattern** — Observed patterns and learned behaviors
- **temporal** — Time-bound facts (use temporal tools for these)

## Cognitive Sectors

OpenMemory automatically classifies memories into cognitive sectors:

- **episodic** — Specific events and experiences
- **semantic** — General facts and knowledge
- **procedural** — How-to knowledge and procedures
- **emotional** — Emotional associations and preferences
- **reflective** — Self-assessments and meta-knowledge

## Setup

```bash
cd /Users/ondrej.levy/Agents/Home
./src/childermass/memory_mcp/setup.sh
```

Or manually:

```bash
pip install -r src/childermass/memory_mcp/requirements.txt
```

## Running

```bash
PYTHONPATH=src python -m childermass.memory_mcp.server
```

## Testing

```bash
PYTHONPATH=src python -m pytest src/childermass/memory_mcp/tests/ -v
```

## Configuration

Environment variables (all optional, defaults are fine for local use):

| Variable | Default | Description |
|----------|---------|-------------|
| `OM_DB_URL` | `sqlite:///<module>/data/memory.sqlite` | Database URL |
| `OM_EMBEDDINGS` | `synthetic` | Embedding engine (synthetic = no API needed) |
| `OM_TIER` | `smart` | Processing tier |

## Security

- Input validation on all parameters (length, format, whitelist)
- Rate limiting per operation (token bucket algorithm)
- Error sanitization strips file paths, SQL, and API keys
- Audit logging to `~/.childermass/memory-audit.log`
- No external API calls needed (local-only with synthetic embeddings)
