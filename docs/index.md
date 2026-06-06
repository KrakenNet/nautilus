# Nautilus

Nautilus is a policy-first data broker for AI agents. A single
`broker.request(...)` call plans an intent, routes it to the right sources,
enforces CLIPS-backed scope rules, executes adapters concurrently, and emits
a signed attestation plus a complete audit entry.

Current release: `nautilus-rkm` 0.1.0 (requires Python 3.14+).

## Start here

- [Getting Started](getting-started.md) — install, configure, first request.

## Documentation by quadrant

The docs follow the [Diataxis](https://diataxis.fr) framework.

### Learn — Concepts

- [Architecture](concepts/architecture.md) — broker pipeline, adapter model, policy routing
- [The Attestation Chain](concepts/attestation-chain.md) — tokens, sinks, hash-chained logs
- [RKM: the Rule Lifecycle](concepts/rkm-lifecycle.md) — propose, validate, review, trace

### Solve a task — How-to Guides

- [Operator Guide](how-to/operator-guide.md) — deploy end to end
- [Authoring Rules](how-to/authoring-rules.md) — write, validate, and test routing rules
- [Developing Adapters](how-to/developing-adapters.md) — scaffold and ship a custom adapter
- [All how-to guides and recipes](how-to/index.md)

### Look up — Reference

- [Python SDK](reference/python-sdk.md) — `Broker`, `BrokerResponse` API
- [REST API](reference/rest-api.md) — `/v1/request`, health probes
- [CLI](reference/cli.md) — `serve`, `key`, `rules`, `adapters`, `attestation`, `rkm`
- [Rule Packs](reference/rule-packs.md) — NIST, HIPAA routing rules
- [Adapter SDK](reference/adapter-sdk.md) — build third-party adapters
