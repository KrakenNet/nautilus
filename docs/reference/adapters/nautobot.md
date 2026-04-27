# Nautobot Adapter

## Description

The Nautobot adapter brokers GraphQL-primary, REST-fallback queries
against [Nautobot](https://docs.nautobot.com/) v3.1. It ships as the
external package `nautilus-adapter-nautobot` and is registered via the
`[project.entry-points."nautilus.adapters"]` table.

GraphQL is preferred because Nautobot's Django object-permissions apply
natively to the GraphQL list resolvers — the broker therefore inherits
Nautobot's existing tenant model rather than duplicating it. REST
fallback covers five Nautobot capabilities the v3.1 GraphQL schema does
not expose directly: writes (rejected in v1), total-count pagination,
`?include=config_context`, IP-to-interface M2M, and device-cluster
assignments.

## Use cases

* Network-automation agents looking up device inventory, interfaces, IP
  prefixes, or assignments without hand-rolling per-tenant REST shims.
* Compliance / inventory rules that need attestation-grade access to
  network source-of-truth.
* Multi-tenant deployments where each Nautilus source carries its own
  Nautobot bot user — see "Bot user provisioning" below.

## Config schema

```yaml
sources:
  - id: nautobot-prod
    type: nautobot
    description: Nautobot 3.1 source-of-truth
    classification: internal
    data_types: [device, interface, ipam_prefix, ipam_ip, config_context]
    url: ${NAUTOBOT_URL}
    token_secret_ref: vault://secret/data/nautobot#token
```

The adapter accepts either an explicit `url` field or a plain
`connection` string. Secret references for `token_secret_ref` may use
`vault://`, `env://`, or a raw `${VAR}` interpolated literal — the
adapter resolves through the broker's secret-provider registry.

## Endpoint / capability coverage matrix

| Capability | Path | Support | Notes |
|---|---|---|---|
| Devices list | GraphQL `devices` | ✅ First-class | Pagination via `(limit, offset)`. |
| Interfaces list | GraphQL `interfaces` | ✅ First-class | |
| IPAM prefixes | GraphQL `prefixes` | ✅ First-class | |
| IPAM IP addresses | GraphQL `ip_addresses` | ✅ First-class | |
| Config contexts | GraphQL `config_contexts` | ✅ First-class | |
| Custom-field discovery | GraphQL `__type(name:"DeviceType")` | ✅ First-class | Prefix introspected at `connect()`; defaults to `cf_`. |
| Total-count pagination metadata | REST list endpoints | ⚠️ REST fallback | Use `data_type=total_count_devices`. |
| Devices with `?include=config_context` | REST `/api/dcim/devices/` | ⚠️ REST fallback | Use `data_type=device_with_config_context`. |
| IP-to-interface M2M | REST `/api/ipam/ip-address-to-interface/` | ⚠️ REST fallback | Use `data_type=ip_address_to_interface`. |
| Device-cluster assignments | REST `/api/dcim/device-cluster-assignments/` | ⚠️ REST fallback | Use `data_type=device_cluster_assignment` (v3 M2M, was v2 FK). |
| Writes (create / update / delete) | any | ❌ Rejected | `NautobotUnsupportedOperation`. Tracked for v2. |

The adapter accepts an arbitrary REST GET path via the
`data_type=rest:<path>` escape hatch; the path must remain on the same
host as the configured base URL (cross-host redirects raise
`SSRFBlockedError`).

## Query language

The adapter relies on Nautobot's **server-side** query language: GraphQL
queries are issued verbatim from a small set of built-in templates that
exercise the v3.1 polymorphic filter (named `type`, **not** the v2
`_type`). Scope constraints are intentionally NOT translated into
GraphQL filters in v1 — Nautobot enforces tenant separation through
object permissions on the bot user (see TD-12 below).

If a predicate cannot be expressed by Nautobot-side permissions, apply
post-filtering at the broker rule layer before persisting the rows.

## Auth

| Mode | Behavior |
|---|---|
| `auth.type=bearer` (config block) | Token forwarded as `Authorization: Token <token>` (Nautobot's native scheme — note `Token`, not `Bearer`). |
| `token_secret_ref` (URI) | Resolved via secret provider before `connect()`. |
| `${NAUTOBOT_TOKEN}` env var fallback | Used if neither of the above is set. |

Tokens are never logged; secret-provider failures raise typed
`ConfigError` without leaking the path.

### Bot user provisioning (TD-12)

Provision **one Nautobot bot user per `SourceConfig`**. Each token
identifies a distinct Nautobot user; grant each only the object
permissions the downstream consumers require. There is intentionally no
broker-side tenant abstraction — Nautilus treats each `source_id` as the
unit of scope, and Nautobot's object-permission engine enforces what
each token can see.

> **Warning — silent-filter behaviour (AC-1.9).** Nautobot's GraphQL
> resolvers apply object-permission denial **silently**: a denied query
> returns HTTP 200 with `{data: {<resource>: []}, errors: []}`. There is
> no 403 outside the envelope, and `errors` is empty. The adapter
> therefore cannot distinguish denial from a legitimate empty result at
> the transport layer — operators must consult Nautobot's audit log when
> a query looks suspicious, and rule authors should not infer
> permission state from broker output alone. The captured cassette at
> `tests/fixtures/nautobot/graphql_permission_denied_probe.yaml` pins
> this behaviour against a Nautobot 3.1 testcontainer.

## Error mapping

| Nautobot response | Adapter outcome |
|---|---|
| HTTP 200 with `data` populated | rows returned |
| HTTP 200 with `{data, errors}` and partial `data` | rows + warnings; audit warning emitted |
| HTTP 200 with `{data: null, errors: [...]}` | `error_type="graphql_no_data"` |
| HTTP 401 / 403 | `error_type="auth_error"` (with `kind=forbidden \| missing_token`) |
| HTTP 5xx | retried with exponential backoff up to 3 attempts; persistent failure → `execution_error` |
| Cross-host redirect | `SSRFBlockedError` |
| RFC 1918 / loopback IP base URL | refused at `connect()` |
| Non-GET method | `NautobotUnsupportedOperation` (v1 is read-only) |

## Example YAML

```yaml
sources:
  - id: nautobot-prod
    type: nautobot
    description: Nautobot 3.1 source-of-truth (devices, IPAM, config-context)
    classification: internal
    data_types: [device, interface, ipam_prefix, ipam_ip, config_context]
    url: https://nautobot.internal.example.com
    token_secret_ref: vault://secret/data/nautobot#token

  - id: nautobot-cluster-assignments
    type: nautobot
    description: REST fallback for device-cluster assignments (v3 M2M)
    classification: internal
    data_types: [device_cluster_assignment]
    url: https://nautobot.internal.example.com
    token_secret_ref: env://NAUTOBOT_TOKEN
```

## Testing

* Unit: `packages/nautilus-adapter-nautobot/tests/unit/` — covers
  custom-field prefix introspection, error mapping, GraphQL client,
  REST fallback, SSRF defenses.
* Integration (replay): `packages/nautilus-adapter-nautobot/tests/integration/`
  runs against the four cassettes under `tests/fixtures/nautobot/`.
* Integration (live record): `VCR_MODE=record uv run pytest -m nautobot_live
  packages/nautilus-adapter-nautobot/tests/integration/` spins
  `networktocode/nautobot:3.1` (with bundled Postgres + Redis) via
  testcontainers and re-records every cassette.
* The OQ-1 permissions spike at
  `tests/integration/test_nautobot_permissions_spike.py` pins the
  silent-filter behaviour described above.

## Out of scope (v1)

* Writes — device / IP / interface creation. Tracked for v2.
* Polymorphic resolvers beyond the five built-in queries — extend by
  adding a query template under `nautilus_adapter_nautobot.graphql`.
* Per-broker tenant abstraction — provision one bot user per source.
