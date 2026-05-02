# Changelog

All notable changes to `nautilus-rkm` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5] - 2026-05-01

### Added
- `BrokerRequest.fact_set_hash` and `Broker.{request,arequest}(..., fact_set_hash=...)` keyword surface so callers can pin a request to a specific fact-set snapshot
- `BrokerResponse.fact_set_hash` echoes the caller's hash back on success
- `BrokerResponse.cap_breached` and `BrokerResponse.source_session_signatures` re-introduced (defaulted `None`) for forward-compat with budget-cap and per-source signature surfaces

## [0.1.4] - 2026-05-01

### Fixed
- Restore Python 3.13 compatibility: replace bare `except A, B:` (Python 3.14 syntax) with `except (A, B):` in `analysis/fallback.py`, `forensics/handoff_worker.py`, `ui/router.py`, and `ui/audit_reader.py`
- Lower `[tool.ruff] target-version` from `py314` to `py313` to keep parens on multi-exception except clauses

## [0.1.1] - 2026-04-17

### Fixed
- CI badge and clone URLs updated to KrakenNet organization
- Documentation site links corrected
- CI workflows updated to trigger on `main` branch
- Documentation deployment workflow improvements

## [0.1.0] - 2026-04-17

### Added
- Core `Broker` facade with sync/async APIs (`request`, `arequest`, `from_config`, `afrom_config`)
- Fathom-based policy router for intent-aware source selection and scope enforcement
- Eight built-in adapters: PostgreSQL, PgVector, Elasticsearch, Neo4j, REST, ServiceNow, InfluxDB, S3
- Pluggable adapter protocol with entry-point discovery
- Ed25519 JWS attestation service for signed routing decisions
- JSONL audit sink with per-request append-only entries
- Pattern-matching and LLM-based intent analysis (Anthropic, OpenAI providers)
- Cross-agent handoff reasoning with session-backed escalation detection
- FastAPI REST transport (`POST /v1/request`, health/readiness probes)
- MCP transport (stdio and HTTP modes)
- CLI: `nautilus serve`, `nautilus health`, `nautilus version`
- YAML configuration with environment variable interpolation
- Rule packs: `data-routing-nist`, `data-routing-hipaa`
- Adapter SDK (`nautilus-adapter-sdk`) with compliance test suite
- OpenTelemetry instrumentation (optional `otel` extra)
- Air-gapped mode (`--air-gapped`) forcing pattern analyzer
