# Changelog

All notable changes to `nautilus-rkm` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2](https://github.com/KrakenNet/nautilus/compare/v0.2.1...v0.2.2) (2026-06-25)


### Documentation

* fix doubled slash docs URLs ([#133](https://github.com/KrakenNet/nautilus/issues/133)) ([84a3e0e](https://github.com/KrakenNet/nautilus/commit/84a3e0ecad21c6053d681be16a7f42146d34510f))
* fix HIPAA rule-pack entry point ([#134](https://github.com/KrakenNet/nautilus/issues/134)) ([7a67868](https://github.com/KrakenNet/nautilus/commit/7a67868ed4104dab4ab2d782068c636e5228d544))
* fix quickstart Python version ([#132](https://github.com/KrakenNet/nautilus/issues/132)) ([32eacbf](https://github.com/KrakenNet/nautilus/commit/32eacbf2be0c2f6fe819626209059474be605ec6))
* update current version in README ([#135](https://github.com/KrakenNet/nautilus/issues/135)) ([48083bb](https://github.com/KrakenNet/nautilus/commit/48083bbaeead2149c061f1f72044e121c05b2a6d))

## [0.2.1](https://github.com/KrakenNet/nautilus/compare/v0.2.0...v0.2.1) (2026-06-24)


### Bug Fixes

* **ci:** repair invalid Dependabot cooldown (semver-*-days unsupported for non-semver ecosystems) ([#71](https://github.com/KrakenNet/nautilus/issues/71)) ([af70491](https://github.com/KrakenNet/nautilus/commit/af70491fa353fd7fe361b250d269fd6c77be81d2))
* use `cooldown.default-days` only — valid for every ecosystem. Validated against Dependabot's own config check on this PR before merge. ([af70491](https://github.com/KrakenNet/nautilus/commit/af70491fa353fd7fe361b250d269fd6c77be81d2))

## [0.2.0](https://github.com/KrakenNet/nautilus/compare/v0.1.3...v0.2.0) (2026-06-24)


### Features

* **analysis:** auto-generate intent vocabulary from SourceConfig.data_types ([#24](https://github.com/KrakenNet/nautilus/issues/24)) ([#44](https://github.com/KrakenNet/nautilus/issues/44)) ([3a71374](https://github.com/KrakenNet/nautilus/commit/3a7137470ca9c4d462006a5a0426f9d899e1f9b8))
* **attestation:** live signing-key rotation + lazy token re-sign ([#25](https://github.com/KrakenNet/nautilus/issues/25)) ([#47](https://github.com/KrakenNet/nautilus/issues/47)) ([9072760](https://github.com/KrakenNet/nautilus/commit/9072760b5837ef092ddf7c4a445ed282646aa666))
* **attestation:** per-source adapter response hashing + attestation linkage ([#19](https://github.com/KrakenNet/nautilus/issues/19)) ([cb5808a](https://github.com/KrakenNet/nautilus/commit/cb5808a2cbecda3de450e44aefdfc8be4ad83601))
* **attestation:** session-token plumbing — issue, verify, handoff gate, audit events ([#46](https://github.com/KrakenNet/nautilus/issues/46)) ([dee0fdc](https://github.com/KrakenNet/nautilus/commit/dee0fdcd3e2cc2605604e6c529ee165418ba553f))
* **core:** post-run engine consistency checks ([#27](https://github.com/KrakenNet/nautilus/issues/27)) ([#48](https://github.com/KrakenNet/nautilus/issues/48)) ([5bd75a9](https://github.com/KrakenNet/nautilus/commit/5bd75a9329b0905dc102d599baf112636ecdb943))
* **core:** SQLite session store + durable Postgres fallback ([#26](https://github.com/KrakenNet/nautilus/issues/26)) ([#49](https://github.com/KrakenNet/nautilus/issues/49)) ([09eb768](https://github.com/KrakenNet/nautilus/commit/09eb76812fe81303186e698b22ae1c0a9b854825))
* **observability:** structured JSON logging ([#28](https://github.com/KrakenNet/nautilus/issues/28)) ([#50](https://github.com/KrakenNet/nautilus/issues/50)) ([bc577ad](https://github.com/KrakenNet/nautilus/commit/bc577adcf4bbd61cba75d69566209adc2cf25a58))
* **servicenow:** attachment-content fetch for sys_id-pinned sys_attachment queries ([245d1b0](https://github.com/KrakenNet/nautilus/commit/245d1b0fe0515366ba9ab6ab0daed4de6b6ca992))
* **transport:** public REST API for audit queries ([#32](https://github.com/KrakenNet/nautilus/issues/32)) ([#45](https://github.com/KrakenNet/nautilus/issues/45)) ([3b8e407](https://github.com/KrakenNet/nautilus/commit/3b8e407fede1b7d09991571b5b30b44e5dc51caf))


### Bug Fixes

* **attestation:** document capabilities contract instead of typing it (fix CI pyright) ([35019c3](https://github.com/KrakenNet/nautilus/commit/35019c388b4c510c9bcd56cebac828601a444a9c))
* **attestation:** never trust adapter-supplied response_hash; persist per-source digests to audit ([f80d333](https://github.com/KrakenNet/nautilus/commit/f80d333857412043d6c6157861092f39bd9cdf90))
* **attestation:** per-source adapter response hashing + attestation linkage ([b2c450b](https://github.com/KrakenNet/nautilus/commit/b2c450b10ccbbf7ce203e6606ccb2631ed069e97))
* **attestation:** record per-source digests on primary audit entry; declare capabilities contract ([bb25179](https://github.com/KrakenNet/nautilus/commit/bb251792d1e5c3d4dba4c1027f71540793cbc948))
* make onboarding guide runnable and prometheus import optional ([ae99b39](https://github.com/KrakenNet/nautilus/commit/ae99b39a4d49af3c77bc47b122721c17c0b1cae0))
* make onboarding guide runnable and prometheus import optional ([f8c70ed](https://github.com/KrakenNet/nautilus/commit/f8c70ed2c9d1eb0b9678051342118a14dc0a8fc5))
* **meta:** crisper description, repair dead docs URL, enrich keywords/classifiers, add llms.txt ([#69](https://github.com/KrakenNet/nautilus/issues/69)) ([58c4b6d](https://github.com/KrakenNet/nautilus/commit/58c4b6d510649c8a99f23d03f40232d427cfb89b))
* Py2 except-syntax bugs blocking import + bump to 0.1.4 ([e25a712](https://github.com/KrakenNet/nautilus/commit/e25a712f979beeda1d8f8781cbeb8dd5201a1a02))
* re-apply except-paren fixes + lower ruff target-version to 3.13 ([685ebe6](https://github.com/KrakenNet/nautilus/commit/685ebe6f8477f3cf3810f4e2f098f927cde3e831))
* replace Py2 'except A, B:' with Py3 'except (A, B):' ([1ff8d58](https://github.com/KrakenNet/nautilus/commit/1ff8d584665fcd45e2860e1471707e6c13344ebe))
* sync nautilus/__init__.py __version__ to 0.1.4 ([b32fb7b](https://github.com/KrakenNet/nautilus/commit/b32fb7b11b7230efa297e6091ddaafac751a813c))


### Documentation

* operator guide, rule-authoring guide, recipes, concepts ([#33](https://github.com/KrakenNet/nautilus/issues/33)) ([#54](https://github.com/KrakenNet/nautilus/issues/54)) ([bd3140c](https://github.com/KrakenNet/nautilus/commit/bd3140c2c8c4531889c1374fa733c959eba38136))
* **rest:** clarify NOT IN default builder is fail-closed, not a stub ([377a962](https://github.com/KrakenNet/nautilus/commit/377a962c6871fe199640143278a55d1f6e831df5))
* update harbor references to stargraph after repo rename ([730c440](https://github.com/KrakenNet/nautilus/commit/730c440eb70c306b7485d0117a768e05317b5c9e))

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
