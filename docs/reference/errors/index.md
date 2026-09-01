# Error reference

Every message Nautilus can put in front of you, quoted as the source emits it, with what it
means, why it happened, and what to do. Search this section for the literal text you saw.

## The three surfaces

| Surface | Shape | Example |
| --- | --- | --- |
| REST / admin console | JSON body `{"detail": "..."}` with an HTTP status | `401 {"detail":"Invalid API key"}` |
| MCP | tool error carrying the same sentence (`ValueError` in `nautilus/transport/mcp_server.py`) | `This credential is bound to agent_id='analyst', so it cannot ask as 'other'` |
| CLI | `ERROR: `, `WARN: `, `FAIL: ` on **stderr** (`nautilus/cli/_common.py:91-101`) | `ERROR: config path does not exist or is not a file: /nope.yaml` |
| Python API | an exception from `nautilus.core`, `nautilus.config`, `nautilus.adapters`, `nautilus.rkm` | `ConfigError: Duplicate source id='s1'` |

CLI exit codes (`nautilus/cli/_common.py:5-7`): **0** success, **1** user error, **2**
validation/policy failure. Code 3 is deliberately never used.

Route-by-route and flag-by-flag context lives in the
[REST API reference](../rest-api.md) and the [CLI reference](../cli.md); this section is the
string index into both.

## Reading a quoted message

Headings on these pages are the exact string in the source. Where the source uses an f-string,
the heading shows the template and the entry says what interpolates:

- `{name}` — a value substituted with `str()`.
- `{name!r}` — substituted with `repr()`, so a string arrives quoted: `rule not found: 'my_rule'`.
- `{exc}` — the text of a wrapped, lower-level exception. The sentence before the colon is
  Nautilus; the sentence after it is the driver, the OS, or a parser.

## A scratch broker

Every `curl` on these pages runs against this. It needs no database and no driver. It is the
[REST API reference's scratch broker](../rest-api.md#running-the-examples) narrowed until it
fails: keys bound to an agent and a narrow capability list, and `api.max_request_bytes` at 4096 so
the body limit is reachable by hand. It binds `127.0.0.1:8001`, not the `127.0.0.1:8000` the API
reference uses, so both can run side by side.

```bash
mkdir -p /tmp/nautilus-errors && cd /tmp/nautilus-errors
cat > nautilus.yaml <<'YAML'
sources:
  - id: notes
    type: static
    classification: unclassified
    data_types: [note]
    allowed_purposes: [research]
    rows:
      - {id: 1, body: "hello"}
agents:
  analyst:
    id: analyst
    clearance: unclassified
    compartments: []
    default_purpose: research
audit:
  path: ./audit.jsonl
attestation:
  enabled: true
api:
  max_request_bytes: 4096
  keys:
    - key: query-key
      agent_id: analyst
      capabilities: [query]
    - key: govern-key
      agent_id: reviewer
      capabilities: [query, govern, audit_read, keys]
YAML
```

<!-- not-executed: blocks until interrupted; run it in a second terminal -->
```bash
cd /tmp/nautilus-errors && nautilus serve --config nautilus.yaml --bind 127.0.0.1:8001
```

Every `curl` on every page of this section writes its base URL as `$NAUTILUS`. Export it once per
shell — nothing else on these pages needs a placeholder filled in:

```bash
export NAUTILUS=http://127.0.0.1:8001
```

Confirm the broker is up before using the `curl` examples. `{"status":"ok"}` means go; a
`{"status":"not_ready", …}` body is explained in
[transport.md](transport.md#readyz-refusal-payloads):

<!-- not-executed: needs the scratch broker from the block above -->
```bash
curl -s "$NAUTILUS/readyz"; echo
```

## Find your message

### Credentials, capabilities, identity — [auth.md](auth.md)

| Message | Status |
| --- | --- |
| `Not authenticated` | 401 |
| `API key required` | 401 |
| `Invalid API key` | 401 |
| `This credential does not hold the {capability!r} capability (it holds {sorted(held)})` | 403 |
| `This credential is bound to agent_id={bound!r}, so it cannot ask as {body.agent_id!r}` | 403 |
| `This credential is bound to agent_id={bound!r}, so it cannot mint a session token for {requested_agent!r}` | 403 |
| `Forwarded identity rejected: peer is not a trusted proxy` | 401 |
| `Missing X-Forwarded-User` | 401 |
| `X-Nautilus-Reviewer header required` | 400 |
| `api.keys is empty, so every data and governance route will answer 401 Not authenticated. …` | log warning |
| `api.keys[0] is a bare string: bound to no agent_id, …` | log warning |
| `api.auth.mode 'proxy_trust' requires api.auth.trusted_proxies. …` | startup |
| `api.auth.trusted_proxies entry {entry!r} is not an address or CIDR block: {exc}` | startup |
| `api.keys entry declares unknown capabilities {unknown}. Known capabilities: {list(CAPABILITIES)}` | startup |

### Session tokens — [session-tokens.md](session-tokens.md)

| Message | Reason code |
| --- | --- |
| `Invalid session token: {exc.reason_code}` | (401 wrapper) |
| `Invalid session token ({exc.reason_code}): {exc}` | (401 wrapper) |
| `No token provided` | `missing` |
| `session_token must be a string` | `missing` |
| `Cannot decode token header` | `bad_signature` |
| `Invalid signature` | `bad_signature` |
| `Token decode failed` | `bad_signature` |
| `Token header missing kid` | `unknown_kid` |
| `Unknown kid: {kid!r}` | `unknown_kid` |
| `Key {kid!r} has been revoked` | `unknown_kid` |
| `Token has expired` | `expired` |
| `Token issued for {broker_instance_id!r}, not {self._broker_instance_id!r}` | `broker_instance_mismatch` |
| `session token was minted for agent {claims.agent_id!r}, presented by {agent_id!r}` | `agent_mismatch` |
| `session tokens are disabled (session_tokens.enabled: false)` | — |
| `purpose {purpose!r} is not one of the purposes agent {agent_id!r} may claim ({sorted(record.allowed_purposes)})` | — |
| `Unknown agent id='{agent_id}'` | — |

### Sessions, exposure ledger, session store — [sessions.md](sessions.md)

| Message |
| --- |
| `session_not_yours: session {state.session_id!r} belongs to another principal. …` |
| `Broker busy: waited {budget}s to take the exposure ledger on {what!r} and did not get it. …` |
| `PostgresSessionStore unavailable (dsn={self._sanitized_dsn()}): {exc}` |
| `PostgresSessionStore unavailable (dsn=…) and sqlite fallback at {self._sqlite_path} failed: {sqlite_exc}` |
| `PostgresSessionStore.aget() called before setup() succeeded` |
| `PostgresSessionStore.aupdate() called before setup() succeeded` |
| `SqliteSessionStore({self._path}) used before setup() succeeded` |
| `session-store pool exhausted: no connection became free within {…}s …` |
| `session-store lock pool exhausted: no connection became free within {…}s …` |
| `session database carries schema version {…}; this build understands version {_SCHEMA_VERSION}. …` |
| `session store at {…} now carries schema version {…}; …` |
| `session database {self._path} carries schema version {found}; …` |
| `session database {self._path} now carries schema version {found}; …` |
| `session_store.backend: redis has no implementation. …` |
| `session_store.backend=postgres requires 'dsn' or TEST_PG_DSN env var` |
| `ERROR: pass exactly one of --sqlite-path or --dsn` |
| `ERROR: no such file: {path}` |
| `ERROR: asyncpg is not installed` |
| `ERROR: could not connect: {exc}` |
| `ERROR: could not read nautilus_schema_version: {exc}` |
| `ERROR: nautilus_schema_version holds no row` |

### HTTP transport — [transport.md](transport.md)

| Message | Status |
| --- | --- |
| `Broker not ready` | 503 |
| `Request body is {declared} bytes; this broker accepts at most {limit} (api.max_request_bytes).` | 413 |
| `request body exceeded api.max_request_bytes ({self.max_bytes} bytes)` | connection abort |
| `Broker busy: {limit} requests are already in flight (api.max_concurrent_requests). Retry.` | 503 |
| `Nautilus could not record this request and will not serve what it cannot account for: {exc}` | 503 |
| `context['scope_constraints'] entry is not a scope constraint: {reasons}` | 400 |
| `invalid datetime: {value!r}` | 400 |
| `Adapter '{name}' not found` | 404 |
| `Adapter '{name}' does not support schema introspection` | 501 |
| `Schema fetch failed: {exc}` | 503 |
| `audit entry not found: {request_id!r}` | 404 |
| `{"status": "not_ready", "reason": "startup_incomplete"}` | 503 |
| `{"status": "not_ready", "reason": "<audit probe text>"}` | 503 |
| `{"status": "not_ready", "reason": "session_store_timeout"}` | 503 |
| `{"status": "not_ready", "reason": "{type(exc).__name__}"}` | 503 |
| `Not Found` | 404 |

### Configuration and startup — [config.md](config.md)

| Message |
| --- |
| `Unable to read config file '{config_path}': {exc}` |
| `Invalid YAML in '{config_path}': {exc}` |
| `Config root must be a mapping, got {type(raw).__name__}` |
| `Interpolated config root must remain a mapping` |
| `Config must define a 'sources' list` |
| `Each source entry must be a mapping` |
| `Each source entry must have a string 'id'` |
| `Duplicate source id='{source_id}'` |
| `Source id='{source_id}' is missing the required key 'type' (one of: {sorted(supported_types)})` |
| `Unsupported source type='{source_type}' for id='{source_id}' (supported: {sorted(supported_types)})` |
| `Missing env var '{var}' referenced by source id='{source_id}'` |
| `Config validation failed:` |
| `source '{self.id}' has type '{self.type}' but no '{required}'. …` |
| `source '{self.id}' has type '{self.type}' but no 'connection'. …` |
| `source id='{source.id}' has type '{source.type}', whose driver is not installed: pip install 'nautilus-rkm[{extra}]' …` |
| `adapters[{i}]: module_path does not exist or is not a file: {module_path}` |
| `adapters[{i}]: cannot import module from {module_path}` |
| `adapters[{i}]: error executing {module_path}: {exc}` |
| `adapters[{i}]: class '{cfg.class_name}' not found in {module_path}` |
| `adapters[{i}]: '{cfg.class_name}' in {module_path} is not a class` |
| `adapters[{i}]: '{cfg.class_name}' in {module_path} does not implement the Adapter protocol (missing: {gaps})` |
| `adapters[{i}]: declared source_type='{cfg.source_type}' does not match {cfg.class_name}.source_type={actual_type!r} in {module_path}` |
| `classification labels are not levels of the 'classification' hierarchy ({known}): …` |
| `analysis.mode={analysis.mode!r} requires analysis.provider to be set` |
| `rkm.auto_promote.enabled: auto-promotion is not implemented. …` |
| `Escalation pack '{yaml_path}' must contain a top-level list, got {type(raw).__name__}` |
| `Each escalation entry in '{yaml_path}' must be a mapping` |

### Adapters and data sources — [adapters.md](adapters.md)

| Message |
| --- |
| `Operator '{op}' not in allowlist: {sorted(_OPERATOR_ALLOWLIST)}` |
| `Invalid field identifier '{f}'` |
| `table name {table!r} has more than one schema qualifier` |
| `Operator '{op}' requires a list value, got {type(bad).__name__}` |
| `Operator 'IN' requires a list value, got {type(value).__name__}` |
| `Operator 'NOT IN' requires a list value, got {type(value).__name__}` |
| `Operator 'LIKE' requires a string value, got {type(bad).__name__}` |
| `Operator 'BETWEEN' requires a 2-tuple/list value` |
| `operator not allowed: {op}` |
| `{Adapter}.execute called before connect()` |
| `{type(self).__name__}: execute failed for source '{source_id}': {type(exc).__name__}: {exc}` |
| `source '{source_id}' declares mTLS but its client certificate could not be loaded …` |
| `RestAdapter refuses private/loopback/link-local IP base URL: {host}` |
| `Refused redirect from host '{base_host}' to different host '{target_host}' (status={…})` |
| `Refused same-host redirect (status={…}); configure the endpoint path directly …` |
| `source '{source_id}' answered with {declared} bytes, over the {MAX_RESPONSE_BYTES}-byte ceiling` |
| `source '{source_id}' object {key!r} is {declared} bytes, over the {MAX_OBJECT_BYTES}-byte ceiling` |
| `ElasticsearchAdapter: field '{field}' is mapped as analysed 'text' with no 'keyword' subfield, …` |
| `ElasticsearchAdapter: the only exact subfield for '{field}' is '{field}.{chosen}', which has ignore_above={limit}, …` |
| `NoopEmbedder(strict=True) cannot produce embeddings. …` |
| `context['embedding'] must be list[float], got {type(override).__name__}` |
| `sn-invalid-field: {field!r}`, `sn-injection-rejected`, `sn-unsupported-operator: {op!r}` |
| `source type '{source_type}' needs its driver: pip install 'nautilus-rkm[{extra}]'` |
| `anthropic extra not installed; install nautilus[llm-anthropic]` |
| `AnthropicProvider: env var {self.api_key_env!r} is unset or empty` |
| …and the per-adapter messages for Postgres, pgvector, Elasticsearch, Neo4j, InfluxDB, S3, ServiceNow, REST, LLM and static. |

### Rules, RKM and the policy engine — [rules.md](rules.md)

| Message |
| --- |
| `ERROR {serr.file}:{serr.line}: {serr.message}{hint_suffix}` |
| `proposed rule {rule_name!r} does not compile: {exc}` |
| `Regression detected: rule {rule_name!r} denies access the current rules grant, in {regression_count} of {replayed} replayed request(s). First: {first_regression}` |
| `proposal not found: {proposal_id!r}` |
| `{"error": "already_decided", "current_status": …}` |
| `cannot transition {proposal_id} from {current!r} to {to!r}` |
| `lock contention timeout on proposal queue` |
| `proposal {proposal.proposal_id!r} carries no rule YAML: artifact has neither 'yaml' nor 'yaml_path' (keys: {sorted(artifact)})` |
| `proposal {proposal.proposal_id!r} references unreadable rule file {path!r}: {exc}` |
| `FathomRouter.reload_rule failed for proposal {proposal_id!r}: {exc}` |
| `cannot promote rule {rule_name!r}: no rules.user_rules_dirs is configured, …` |
| `cannot promote rule {rule_name!r}: writing {target} failed: {exc}` |
| `cannot retract rule {rule_name!r}: it is still in force after a rebuild, …` |
| `rule not found: {rule_name!r}` |
| `rule {rule_name!r} version {to_version} not found` |
| `rule {rule_name!r} v{to_version} not found in lineage` |
| `lineage record not found: {rule_name} v{version}` |
| `invalid rule name {rule_name!r}: expected a bare rule name, optionally prefixed 'module::'` |
| `rule pack {pack_name!r} is claimed by more than one installed distribution …` |
| `Fathom engine construction failed: {exc}` |
| `FathomRouter.route() failed for agent_id={agent_id!r}: {exc}` |
| `routing_unknown_source`, `scope_without_routing`, `denial_unknown_source`, `denial_missing_linkage`, `agent_fact_integrity`, `session_exposure_count` |
| `rule {rule_name!r} targets routing-owned template {template!r}` |
| `{path}:{approx_line}: invalid relationship_type={rel_type!r}; must be one of [{valid}]` |
| `body must carry 'rule_yaml': the contents of the rule file` |
| `reason is required for rejection`, `reason is required for retraction`, `to_version is required for rollback`, `yes=true required for destructive operation` |

### Attestation, keys and the chained log — [attestation.md](attestation.md)

| Message |
| --- |
| `kid must be a UUID` |
| `reviewer is required (no control characters)` |
| `reviewer and reason are required (no control characters)` |
| `kid {kid!r} not found` |
| `kid {kid!r} is the current primary; rotate first, then revoke` |
| `Key {entry.kid!r} has no private key (revoked)` |
| `Expected Ed25519PrivateKey` / `Expected Ed25519PublicKey` |
| `attestation is disabled` |
| `attestation.sink.chained requires attestation.enabled with a signing key` |
| `audit.chained requires attestation.enabled with a signing key: …` |
| `audit.chained cannot append to the existing chain at {audit_path} with an auto-generated signing key: …` |
| `{subject} is already open for writing by {holder}. A hash chain admits exactly one writer: …` |
| `emit on closed ChainedFileAttestationSink` |
| `unreadable offsets file {path}: {exc}` |
| `refusing non-monotonic save: current={…} < persisted={…}` |
| `AuditRecord has no {NAUTILUS_METADATA_KEY!r} metadata` |

### Command line — [cli.md](cli.md)

| Message | Exit |
| --- | --- |
| `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.` | 1 |
| `ERROR: config path does not exist or is not a file: {config_path}` | 2 |
| `ERROR: invalid config: {exc}` | 2 |
| `ERROR: broker construction failed: {exc}` | 2 |
| `ERROR: file not found: {file_path}` | 1 |
| `--bind must be HOST:PORT, got {bind!r}` | 2 |
| `--bind port must be an integer, got {port_s!r}` | 2 |
| `Unable to read config '{config_path}': {exc}` | 2 |
| `application startup failed; the server never accepted a connection. The cause is logged above.` | 2 |
| `FAIL {status} {url}` / `FAIL unreachable {url}: {exc}` | 1 |
| `WARN: --air-gapped drops LLM source id={…!r} — connection host is not loopback (NFR-1, #43)` | — |
| `ERROR: rkm: no subcommand given (try: queue, lineage)` | 2 |
| `ERROR: rkm queue: no op given (try: submit, list, show, approve, reject, diff)` | 2 |
| `ERROR: rule: no subcommand given (try: list, retract, lineage, history, rollback)` | 2 |
| `ERROR: rules: no subcommand given (try: validate, test, history)` | 2 |
| `ERROR: adapters: no subcommand given (try: new, list, schema, schema-fingerprint, schema-diff, schema-ack)` | 2 |
| `ERROR: key: no subcommand given (try: list, rotate, revoke)` | 2 |
| `ERROR: attestation: no subcommand given (try: verify)` | 2 |
| `ERROR: events: no subcommand given (try: list)` | 2 |
| `ERROR: {target} already exists — refusing to overwrite it` | 1 |
| `FAIL: key {command}: --url is required. …` | 2 |
| `ERROR: rotate requires --yes to confirm.` | 1 |
| `ERROR: revoke requires --yes to confirm.` | 1 |
| `FAIL: key {command}: cannot reach {endpoint}: {exc}` | 2 |
| `ERROR: key {command}: server returned {status_code}: {text}` | 2 |
| `ERROR: --yes required for destructive op` | 1 |
| `ERROR: --reason required for retract` | 1 |
| `ERROR: --cascade and --orphan-children are mutually exclusive` | 1 |
| `ERROR: rule {name!r} not found in lineage` | 1 |
| `ERROR: rule {name!r} v{to_version} not found in lineage` | 1 |
| `WARN: no lineage records for {name!r}` / `WARN: no history for {name!r}` | 0 |
| `ERROR: rule file not found: {rule_path}` | 1 |
| `ERROR: rkm queue approve: --url is required. …` | 2 |
| `ERROR: rkm queue approve: cannot reach {endpoint}: {exc}` | 2 |
| `ERROR: rkm queue approve: server returned {status_code}: {text}` | 2 |
| `ERROR: proposal {proposal_id} not found` | 1 |
| `ERROR: proposal {proposal_id} already decided: status={current_status}` | 1 |
| `WARN: could not read rkm settings from {config_path!r} ({exc}); using defaults` | 0 |
| `WARN: no lineage records for {id!r}` | 0 |
| `ERROR: invalid adapter name {name!r} (expected lowercase-dashed, e.g. my-csv-adapter)` | 1 |
| `ERROR: destination already exists and is not empty: {dest}` | 1 |
| `ERROR: copier is required for 'adapters new' — install it with: pip install copier` | 1 |
| `ERROR: no config found: pass --config PATH, or run from a directory containing nautilus.yaml` | 1 |
| `ERROR: --status {status_filter!r} needs --url: quarantine state lives in the serving process, …` | 1 |
| `ERROR: could not load {config_path}: {exc}` | 1 |
| `ERROR: could not reach {url}: {exc}` | 1 |
| `ERROR: no schema available for adapter {name!r}` | 1 |
| `ERROR: no schema available for adapter {name!r}; cannot ack` | 1 |
| `ERROR: schema-ack requires --yes to confirm` | 1 |
| `WARN: could not read schema for {name!r}: {exc}` | 0 |
| `WARN: no stored fingerprint for {name!r}; treating as new` | 0 |
| `ERROR: attestation verify: log not found: {log_path}` | 1 |
| `ERROR: attestation verify: pubkey not found: {pubkey_path}` | 1 |
| `ERROR: attestation verify: {result.error}` | 2 |
| `WARN: could not read audit path from {config_path!r} ({exc}); using {path}` | 0 |
| `ERROR: audit log not found: {audit_path}` | 1 |
| `ERROR: cannot read rules config from {path}: {exc}` | 1 |
| `ERROR: score {min_total} below threshold {threshold}: {file_path}` | 2 |
| `WARN: no rules found in {file_path}` | 0 |
| `WARN: affected descendants: {names}` | 0 |
| `WARN: rule '{name}': shadow finding {relation} (existing rule '{existing_rule}')` | 0 |
| `WARN: rule '{name}': insufficient audit history (replayed {replayed_n_actual} entries)` | 0 |
| `WARN: rule '{name}': {skipped_drifted} audit entries could not be replayed -- …` | 0 |
| `WARN: rule '{name}': {skipped_no_input_facts} audit entries carry no engine input and were not replayed` | 0 |

### Embedding Nautilus as a library — [library.md](library.md)

| Message |
| --- |
| `Broker.request() called inside a running event loop. Use Broker.arequest() (async) from async contexts.` |
| `Broker.close() called inside a running event loop. Use Broker.aclose() (async) from async contexts.` |
| `Broker.{method}() called after close(); the attestation sink and session store are already shut down, …` |
| `Broker.declare_handoff() failed for source={source_agent_id!r} receiving={receiving_agent_id!r}: {exc}` |
| `create_app requires either config_path or existing_broker` |
| `create_server requires either config_path or existing_broker` |
| `AC-21.b: this adapter must implement get_schema() (task-006)` |
| `adapter id {adapter_id!r} is not usable as a fingerprint filename` |
