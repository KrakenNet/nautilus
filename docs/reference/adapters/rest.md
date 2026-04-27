# REST Adapter

## Description

The REST adapter brokers requests to arbitrary HTTP/JSON APIs that are
not covered by a dedicated first-party adapter. It is the broker's
catch-all for HTTP-shaped data sources, with operator-template rendering,
SSRF defenses, and the optional ingest-integrity hook.

## Use cases

* Threat-intel and advisory feeds that publish a JSON list endpoint.
* Custom internal services that expose a Table-API-style read endpoint
  but do not warrant a bespoke adapter.
* Vendor APIs (e.g. cloud security posture, CVE databases) consumed
  alongside their published OpenAPI schema for ingest-integrity gating.

## Config schema

```yaml
sources:
  - id: advisory-feed
    type: rest
    description: Public CVE advisory feed
    classification: public
    data_types: [advisory]
    connection: https://advisories.example.com
    auth:
      type: bearer
      token: ${ADVISORY_TOKEN}
    endpoints:
      - path: /api/v2/advisories
        method: GET
        query_params: [vendor, severity, published_after]
        operator_templates:
          "=": "{field}={value}"
          ">=": "{field}_gte={value}"
    ingest_integrity:
      schema: ./schemas/advisory-v2.json
      on_schema_violation: quarantine   # quarantine | reject | pass-through
      baseline_window: 7d
      anomaly_sigma: 3.0
      on_publisher_schema_change: pause # pause | warn
```

## Endpoint / capability coverage matrix

| Capability | Support | Notes |
|---|---|---|
| GET (list / item) | ✅ First-class | `EndpointSpec` with operator templates |
| POST / PATCH / PUT / DELETE | ❌ Not covered | v1 adapter is GET-only. |
| Pagination (`Link` header) | ⚠️ Adapter-level template | Caller renders next-cursor in operator templates if needed. |
| Pagination (offset / limit) | ⚠️ Adapter-level template | Same — supplied via `query_params`. |
| Multipart / streaming uploads | ❌ Not covered | Out of v1 scope. |
| Bearer auth | ✅ First-class | Token resolved via secret provider. |
| Basic auth | ✅ First-class | |
| mTLS | ✅ First-class | Cert + key + CA paths. |
| Cross-host redirects | ❌ Rejected | SSRF defense; followed only within the configured base host. |
| RFC 1918 / loopback / link-local IP base URLs | ❌ Rejected | SSRF defense — refused at `connect()`. |
| JSON Schema validation on ingest | ⚠️ Optional | Enable via `ingest_integrity.schema`. |
| Statistical anomaly detection | ⚠️ Optional | Enable via `ingest_integrity.anomaly_sigma`. |
| Publisher-schema-change pause | ⚠️ Optional | Enable via `ingest_integrity.on_publisher_schema_change=pause`. |

## Query language

Operator templates render predicates produced by the router. Each
endpoint declares the operator subset it supports. Operators not on the
allowlist (`adapters/base.py:42-58`) are rejected at validation time.

## Auth

| Mode | Behavior |
|---|---|
| `bearer` | Adds `Authorization: Bearer <token>` to every request. |
| `basic` | HTTP basic auth via `httpx.BasicAuth`. |
| `mtls` | Configures `verify` + cert + key on `httpx.AsyncClient`. |
| `none` | No auth header. |

Tokens are never logged; failures to resolve a secret reference raise a
typed error with the path elided (NFR-SEC-SECRETS).

## Error mapping

| Outcome | Bucket |
|---|---|
| 2xx with rows | `data` populated |
| 4xx auth (401 / 403) | `sources_errored` with `error_type="auth_error"` |
| 5xx after retries | `sources_errored` |
| Cross-host redirect | `sources_errored` with `error_type="SSRFBlockedError"` |
| Timeout / connection refused | `sources_errored` |
| Schema violation in `quarantine` mode | row sent to quarantine sink + audit entry |
| Schema violation in `reject` mode | source returns empty rows + audit warning |
| Publisher schema change in `pause` mode | source skipped with `publisher_schema_changed` |

## Example YAML

```yaml
sources:
  - id: advisory-feed
    type: rest
    description: Public CVE advisory feed
    classification: public
    data_types: [advisory]
    connection: https://advisories.example.com
    auth:
      type: bearer
      token: ${ADVISORY_TOKEN}
    endpoints:
      - path: /api/v2/advisories
        method: GET
        query_params: [vendor, severity]
        operator_templates:
          "=": "{field}={value}"
```

## Testing

* Unit: `tests/unit/adapters/test_rest.py`,
  `tests/unit/adapters/test_rest_ingest.py` (ingest-integrity wiring).
* Integration: `tests/integration/test_rest_e2e.py` runs a uvicorn loopback
  harness for end-to-end coverage.
* Ingest-integrity: `tests/integration/test_ingest_integrity.py` exercises
  the malformed → quarantine, baseline outlier → audit, and
  publisher-schema-change → pause paths.
