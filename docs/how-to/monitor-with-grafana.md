# Monitor with Grafana

Stand up a Prometheus + Grafana view of a running broker.

## Quick start: the full showcase

The repository ships a complete observability stack with pre-provisioned
dashboards:

```bash
cd examples/full-showcase
docker compose up
# Grafana:    http://localhost:3000
# Prometheus: http://localhost:9090
```

Three dashboards are provisioned out of the box
(`examples/full-showcase/grafana/dashboards/`):

- **overview** — request rate, decision distribution (allow/scope/deny),
  error rate, latency histograms (p50/p90/p99).
- **adapters** — per-adapter request breakdown, durations, error counts.
- **attestation** — signing volume and sink behavior.

## Wiring your own deployment

The broker exposes Prometheus metrics at `GET /metrics` on the REST
transport (unauthenticated, excluded from the OpenAPI schema). Scrape it:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: nautilus
    static_configs:
      - targets: ["nautilus-host:8000"]
```

Then either import the showcase dashboard JSON files into your Grafana,
or copy the provisioning setup from
`examples/full-showcase/grafana/provisioning/`.

## Traces and logs

- **Traces** — the broker emits OpenTelemetry spans for each pipeline
  stage (`broker.request` through `attestation.sign`) when an OTel SDK
  + OTLP endpoint are configured; the showcase routes them to Tempo.
- **Logs** — run `nautilus serve --log-format json` and ship the stream
  to your aggregator (the showcase uses Loki). JSON log lines carry
  `request_id` and, when a span is active, `trace_id`/`span_id` — so a
  Grafana panel can pivot log line → trace → audit entry
  (`GET /v1/audit/{request_id}`).

## What to alert on

- `readyz` failures (session-store outage; check
  `session_store_mode: degraded_*` in recent audit entries).
- A rising denial rate — either a misbehaving agent or an
  over-aggressive new rule (correlate with `rule_trace` in audit
  entries; `nautilus rules test` before shipping rules prevents most of
  these).
- Quarantined adapters (`nautilus adapters list --status quarantined`) —
  schema drift detected; resolve with `schema-ack` after review.
