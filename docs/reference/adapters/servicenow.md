# ServiceNow Adapter

## Description

The ServiceNow adapter brokers read access to a ServiceNow instance via the
generic Table API (`/api/now/table/<table>`). It is intentionally GET-only
in v1 — the broker does not own the workflow primitives ServiceNow
admins expect (state transitions, approvals, work-notes append). Treat
this article as the authoritative coverage matrix for the v1 adapter; any
endpoint marked ❌ requires either a follow-up adapter feature or an
out-of-broker integration (typically a ServiceNow scripted REST resource
plus a Nautilus REST adapter pointed at it).

## Use cases

* CMDB enrichment — pull `cmdb_ci_*` records to attach asset metadata to
  agent intents that mention an internal hostname or IP.
* Incident / change context — read existing change-management or incident
  records to inform an agent that is recommending follow-up actions.
* Journal / work-note retrieval — surface the most-recent narrative on a
  ticket without exposing journal append.

## Config schema

```yaml
sources:
  - id: servicenow-prod
    type: servicenow
    description: ServiceNow Table API for CMDB + incident reads
    classification: internal
    data_types: [cmdb_ci, incident]
    connection: https://acme.service-now.com
    auth:
      type: bearer
      token: ${SERVICENOW_TOKEN}
    endpoints:
      - path: /api/now/table/cmdb_ci_server
        method: GET
        query_params: [name, ip_address, fqdn]
        operator_templates:
          "=": "{field}={value}"
          "LIKE": "{field}LIKE{value}"
```

Any operator templates not declared default to a deny — the adapter
refuses to send a query that would attempt an unsupported operator.

## Endpoint / capability coverage matrix

The ServiceNow adapter reaches every Table API resource through the same
generic GET path (`servicenow.py:250`). The matrix below records which
ServiceNow workflow primitives are first-class (specific `EndpointSpec`
helpers, dedicated docs), which are reachable via the generic Table API
(usable but you write the operator templates), and which are out of scope.

| Endpoint / feature | Support | Notes |
|---|---|---|
| Change Management (`sn_chg_rest/change/normal`) create / update / state-transition | ❌ Not covered | Adapter is GET-only. Tracked in follow-up issue — requires adapter POST + state-machine plumbing. |
| Attachments (`sn_ws_attachment`) upload | ❌ Not covered | No multipart POST in the v1 adapter. Tracked in follow-up issue — requires multipart-encoded PUT. |
| Attachments retrieve (`/api/now/attachment`) | ⚠️ Generic Table API | Configurable; see snippet below. |
| CMDB queries (`cmdb_ci_*`) | ⚠️ Generic Table API | Configurable; see snippet below. |
| CMDB relationships (`cmdb_ci_rel_*`) | ❌ Not covered | The adapter does not traverse rel-tables in v1. Tracked in follow-up issue — requires adapter-level join. |
| Task linkage (`task_ci`) read | ⚠️ Generic Table API | Read-only via the generic helper; see snippet below. |
| Task linkage (`task_ci`) create / link | ❌ Not covered | Tracked in follow-up issue — requires adapter POST. |
| Work-notes append | ❌ Not covered | GET-only adapter. Tracked in follow-up issue — requires PATCH against `comments_and_work_notes`. |
| Journal fields read | ⚠️ Generic Table API | Configurable; see snippet below. |
| Journal fields append | ❌ Not covered | GET-only. Tracked in follow-up issue — requires PATCH. |

### ⚠️ Generic Table API examples

#### Attachments retrieve

```yaml
- id: servicenow-attachments
  type: servicenow
  connection: https://acme.service-now.com
  data_types: [attachment]
  endpoints:
    - path: /api/now/attachment
      method: GET
      query_params: [table_name, table_sys_id]
      operator_templates:
        "=": "{field}={value}"
```

#### CMDB queries

```yaml
- id: servicenow-cmdb-server
  type: servicenow
  connection: https://acme.service-now.com
  data_types: [cmdb_ci_server]
  endpoints:
    - path: /api/now/table/cmdb_ci_server
      method: GET
      query_params: [name, ip_address]
      operator_templates:
        "=": "{field}={value}"
        "LIKE": "{field}LIKE{value}"
```

#### Task linkage read

```yaml
- id: servicenow-task-ci
  type: servicenow
  connection: https://acme.service-now.com
  data_types: [task_ci]
  endpoints:
    - path: /api/now/table/task_ci
      method: GET
      query_params: [task, ci_item]
      operator_templates:
        "=": "{field}={value}"
```

#### Journal fields read

```yaml
- id: servicenow-journal
  type: servicenow
  connection: https://acme.service-now.com
  data_types: [journal_field]
  endpoints:
    - path: /api/now/table/sys_journal_field
      method: GET
      query_params: [element_id, name]
      operator_templates:
        "=": "{field}={value}"
```

## Query language

ServiceNow Table API queries are passed via `sysparm_query` with
`field<op>value` predicates. The adapter renders predicates from the
`scope_constraints` produced by the router using each endpoint's
`operator_templates` map. Operators not present in the map are rejected
with a `ScopeEnforcementError`. The full list of supported router
operators is documented in the core scope-constraint reference.

## Auth

* `bearer` — recommended; token resolved through the broker's secret
  provider (env, `vault://secret/data/...#token`).
* `basic` — supported for legacy ServiceNow instances that do not issue
  OAuth tokens.

Tokens are never logged; secret-provider failures raise `ConfigError`
without leaking the requested path or response body.

## Error mapping

| ServiceNow response | Adapter outcome |
|---|---|
| HTTP 200 with `result: [...]` | `AdapterResult.rows` populated |
| HTTP 401 / 403 | `AdapterResult.error` with `error_type="auth_error"` → broker bucket: `sources_errored` |
| HTTP 5xx | retried with exponential backoff up to 3 attempts; persistent failure → `sources_errored` |
| HTTP 200 with `error: {message}` envelope | `sources_errored` with the envelope message |

## Example YAML

```yaml
sources:
  - id: servicenow
    type: servicenow
    description: ServiceNow CMDB + incident reads
    classification: internal
    data_types: [cmdb_ci_server, incident]
    connection: https://acme.service-now.com
    auth:
      type: bearer
      token: ${SERVICENOW_TOKEN}
    endpoints:
      - path: /api/now/table/cmdb_ci_server
        method: GET
        query_params: [name, ip_address]
        operator_templates:
          "=": "{field}={value}"
          "LIKE": "{field}LIKE{value}"
      - path: /api/now/table/incident
        method: GET
        query_params: [number, state]
        operator_templates:
          "=": "{field}={value}"
```

## Testing

The unit test suite at `tests/unit/adapters/test_servicenow.py` covers
operator-template rendering and SSRF defenses. The integration test at
`tests/integration/test_servicenow_e2e.py` uses
`httpx.MockTransport` to replay canned responses — no live ServiceNow
instance is required.

To extend the adapter for a new endpoint not listed above, add an
`EndpointSpec` block under the source's `endpoints:` list and register
the operator templates the agent intents will reference. If the new
endpoint requires write semantics (POST / PATCH), file a follow-up issue
referencing the matrix above — the v1 adapter intentionally rejects
non-GET methods.
