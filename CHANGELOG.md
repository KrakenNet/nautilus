# Changelog

All notable changes to `nautilus` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
