# Changelog

All notable changes to the Childermass Memory MCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-07-19

### Added

#### Memory Tools
- `memory_store()` — Store memories with category classification
- `memory_recall()` — Semantic similarity search across all memories
- `memory_recall_by_sector()` — Filter memories by cognitive sector
- `memory_get()` — Retrieve a specific memory by ID
- `memory_list()` — List memories with optional category filter
- `memory_forget()` — Delete a specific memory

#### Temporal Knowledge Graph Tools
- `memory_store_fact()` — Store time-bound facts (subject-predicate-object)
- `memory_update_fact()` — Update facts with history preservation
- `memory_timeline()` — Get chronological fact history for an entity
- `memory_summary()` — System statistics and overview

#### Categories
- preference, routine, fact, feedback, pattern, temporal

#### Cognitive Sectors (via OpenMemory SDK)
- episodic, semantic, procedural, emotional, reflective

#### Security Features
- Input validation for all parameters
- Rate limiting with token bucket algorithm
- Error sanitization (paths, SQL, API keys)
- Audit logging to `~/.childermass/memory-audit.log`

#### Infrastructure
- OpenMemory Python SDK integration (v1.3.x)
- Local SQLite storage with synthetic embeddings (zero-config)
- Temporal graph for time-evolving facts
- Singleton client pattern with lazy initialization
