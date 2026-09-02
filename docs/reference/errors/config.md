# Configuration and startup

Everything here is fatal at boot: `nautilus serve` prints it and exits **2** before binding a
port. Most are `ConfigError` (`nautilus/config/loader.py:57`); the rest are pydantic validation
errors arriving inside the `Config validation failed:` envelope.

## Reading the file

### `Unable to read config file '{config_path}': {exc}`

`nautilus/config/loader.py:123-126`. `{exc}` is the `OSError` — typically
`[Errno 2] No such file or directory` or `[Errno 13] Permission denied`. Check the path you
passed to `--config`.

### `Invalid YAML in '{config_path}': {exc}`

`nautilus/config/loader.py:128-131`. `{exc}` is the PyYAML parse error, including the line and
column it gave up at. Tabs for indentation and an unclosed `[` are the usual causes.

### `Config root must be a mapping, got {type(raw).__name__}`

`nautilus/config/loader.py:132-134`. The file parsed to a list or a scalar. Rendered example:
`Config root must be a mapping, got list` — a document that starts with `- `.

### `Interpolated config root must remain a mapping`

`nautilus/config/loader.py:136-139`. Environment interpolation replaced the whole document.
Reachable when the root of the file is a single `${VAR}`.

### `Missing env var '{var}' referenced by source id='{source_id}'`

`nautilus/config/loader.py:107-110`. A `${VAR}` reference has no value in the environment.
`{source_id}` is the enclosing source, or `None` for a reference outside any source block.
Rendered example:

```text
Missing env var 'PG_DSN' referenced by source id='vuln_db'
```

This is the first thing the shipped `examples/quickstart/nautilus.yaml` will tell you: it
references `${PG_DSN}`. Export it first.

## The `sources` list

### `Config must define a 'sources' list`

`nautilus/config/loader.py:141-144`. No `sources:` key, or it is not a list. An empty list is
accepted — a broker with no sources starts.

### `Each source entry must be a mapping`

`nautilus/config/loader.py:149-152`. One entry is a bare string or number. A common shape error:
`sources: [postgres]` instead of a list of blocks.

### `Each source entry must have a string 'id'`

`nautilus/config/loader.py:153-156`.

### `Duplicate source id='{source_id}'`

`nautilus/config/loader.py:157` and again in `nautilus/config/registry.py:28`. Source ids key
routing decisions and scope constraints, so they must be unique.

### `Source id='{source_id}' is missing the required key 'type' (one of: {sorted(supported_types)})`

`nautilus/config/loader.py:161-166`. Rendered example:

```text
Source id='s1' is missing the required key 'type' (one of: ['elasticsearch', 'influxdb',
'llm', 'neo4j', 'pgvector', 'postgres', 'rest', 's3', 'servicenow', 'static'])
```

The list is the live `ADAPTER_REGISTRY`, so it grows when you register a custom adapter.

### `Unsupported source type='{source_type}' for id='{source_id}' (supported: {sorted(supported_types)})`

`nautilus/config/loader.py:167-171`. A typo, or a custom adapter that is configured under
`sources:` but not registered under `adapters:`. Also raised later as
`Unsupported source type '{source.type}' for id='{source.id}'`
(`nautilus/core/broker.py:1662`) when the broker builds the adapter.

```bash
python - <<'PY'
import pathlib, tempfile
from nautilus.config.loader import ConfigError, load_config
d = pathlib.Path(tempfile.mkdtemp())
cases = {
  "no-type":   "sources:\n  - id: s1\n",
  "bad-type":  "sources:\n  - id: s1\n    type: nope\n",
  "duplicate": "sources:\n  - id: s1\n    type: static\n  - id: s1\n    type: static\n",
  "no-sources": "api: {}\n",
  "not-mapping": "- 1\n",
  "missing-env": "sources:\n  - id: s1\n    type: postgres\n    connection: ${NAUTILUS_UNSET}\n",
}
for name, text in cases.items():
    p = d / f"{name}.yaml"
    p.write_text(text)
    try:
        load_config(str(p))
    except ConfigError as exc:
        print(f"[{name}] {exc}")
PY
```

## `Config validation failed:`

Two forms, both `ConfigError`:

- `Config validation failed:\n{_redacted_errors(exc)}` — `nautilus/config/loader.py:175-177`,
  one indented `path: message [type=...]` line per pydantic error, with values redacted so a DSN
  or a key never lands in a log.
- `Config validation failed: {exc}` — `nautilus/config/loader.py:178-179`, the fallback.

Rendered example:

```text
Config validation failed:
  sources.0.classification: Field required [type=missing]
  sources.0.data_types: Field required [type=missing]
```

The `path` is a dotted route into the YAML: `sources.0.classification` is the `classification`
key of the first source. `Field required [type=missing]` means the key is absent; every source
needs at least `id`, `type`, `classification` and `data_types`.

### `sources.{i}.id: String should match pattern '^[A-Za-z0-9][A-Za-z0-9._-]*$' [type=string_pattern_mismatch]`

`nautilus/config/models.py:147`. A source id is letters, digits, `.`, `_` and `-`, starting with
a letter or a digit. The bound is there because the id is *reproduced*: it is interpolated into
application log lines, it becomes the OpenTelemetry span name `adapter.<id>`, and it is the
`{name}` segment of `GET /v1/adapters/{name}/schema`. A newline in it used to split one log
record into two, the second reading as a line the broker wrote itself.

```text
Config validation failed:
  sources.0.id: String should match pattern '^[A-Za-z0-9][A-Za-z0-9._-]*$' [type=string_pattern_mismatch]
```

The anchors are exact rather than lenient: a *trailing* newline is refused too. Rename the source;
nothing downstream stores the old id except the audit entries already written, which keep it.

Nautilus's own validators appear here as `Value error, <message>`:

### `source '{self.id}' has type '{self.type}' but no '{required}'. The {self.type} adapter requires it, so every request to this source would fail at runtime.`

`nautilus/config/models.py:212-217`. `{required}` is the per-type key — `table` for `postgres`
and `pgvector`, `index` for `elasticsearch`, `label` for `neo4j`, `model` for `llm`.

### `source '{self.id}' has type '{self.type}' but no 'connection'. The {self.type} adapter has nothing to dial, so every request to this source would fail at runtime.`

`nautilus/config/models.py:219-223`.

### `analysis.mode={analysis.mode!r} requires analysis.provider to be set`

**`ConfigError`**, `nautilus/core/broker.py:1448-1452`. `analysis.mode: llm` needs a provider
block. Either add one, or return to `analysis.mode: pattern`.

### `rkm.auto_promote.enabled: auto-promotion is not implemented.` …

`nautilus/config/models.py:701-705`. Startup refuses rather than silently ignoring the key. In
full:

```text
rkm.auto_promote.enabled: auto-promotion is not implemented. Every proposal routes to the
human-review queue (`nautilus rkm queue`, `POST /v1/rkm/queue/{id}/approve`); remove the key
or set it to false.
```

### `classification labels are not levels of the 'classification' hierarchy ({known}): {errors}`

**`ConfigError`**, `nautilus/core/broker.py:682-687`. `{known}` is the configured hierarchy;
`{errors}` is a `; `-joined list naming each offender, in one of three shapes:
`sources['s1'].classification='secret'`, `agents['analyst'].clearance='secret'`, or
`escalation rule 'r1'.resulting_level='secret'`.

**Means.** A label was used that the hierarchy does not define, so it could not be ordered
against any other label. Add the level to the hierarchy, or correct the spelling.

Auth-related validation errors — `proxy_trust` without `trusted_proxies`, malformed CIDRs and
unknown capabilities — are in [auth.md](auth.md). Session-store validation is in
[sessions.md](sessions.md).

## Custom adapters under `adapters:`

Raised by `Broker._load_custom_adapters` (`nautilus/core/broker.py:396-441`). `{i}` is the index
in the `adapters:` list, so `adapters[0]:` is the first entry.

| Message | Cause |
| --- | --- |
| `adapters[{i}]: module_path does not exist or is not a file: {module_path}` | Path is wrong or points at a directory. It is resolved relative to the process working directory unless absolute. |
| `adapters[{i}]: cannot import module from {module_path}` | Python could not build a module spec — usually not a `.py` file. |
| `adapters[{i}]: error executing {module_path}: {exc}` | The module raised while being imported. `{exc}` is that exception; a missing third-party import is the usual one. |
| `adapters[{i}]: class '{cfg.class_name}' not found in {module_path}` | The module imported but has no such attribute. Check spelling and that the class is at module level. |
| `adapters[{i}]: '{cfg.class_name}' in {module_path} is not a class` | The name resolves to a function or an instance. |
| `adapters[{i}]: '{cfg.class_name}' in {module_path} does not implement the Adapter protocol (missing: {gaps})` | `{gaps}` names the missing members — `connect`, `execute`, `close`. |
| `adapters[{i}]: declared source_type='{cfg.source_type}' does not match {cfg.class_name}.source_type={actual_type!r} in {module_path}` | The `source_type` in config disagrees with the class attribute. Two names for one adapter is a routing bug waiting to happen. |

### `source id='{source.id}' has type '{source.type}', whose driver is not installed -- {install_extra_hint(extra)} (import failed: {…})`

**`ConfigError`**, `nautilus/core/broker.py:1669-1674`. The source type is built in, but its
optional driver is not installed, so `nautilus.adapters` registered a stand-in. The parenthesised
text is the original `ImportError`. `{install_extra_hint(extra)}` names both ways to obtain the
extra ([index.md](index.md#reading-a-quoted-message)); on the published container image only the
`image:` half applies, because there is no `pip` in it. In full, for a `postgres` source:

```
ERROR: invalid config: source id='rows' has type 'postgres', whose driver is not installed -- host: pip install 'nautilus-rkm[postgres]'; image: docker build --build-arg EXTRAS="--extra postgres" . (the published image installs --extra otel only, and has no shell or pip to add to it) (import failed: No module named 'asyncpg')
```

Install the extra, rebuild the image with it, or remove the source.

## Escalation packs

### `Escalation pack '{yaml_path}' must contain a top-level list, got {type(raw).__name__}`

`nautilus/config/escalation.py:52-56`.

### `Each escalation entry in '{yaml_path}' must be a mapping`

`nautilus/config/escalation.py:58-60`.

## What the CLI shows

`nautilus serve` wraps the above (`nautilus/cli/serve.py:355-396`):

```text
ERROR: config path does not exist or is not a file: {config_path}
ERROR: invalid config: {exc}
ERROR: broker construction failed: {exc}
```

`nautilus config check <path>` prints the same three, with the same exit **2**, without starting
anything: it calls the same function. That is how you read these messages before a deployment
rather than after one — see
[Check what you are about to deploy](../../how-to/operator-guide.md#the-config).

The first is checked before the file is opened; the second wraps `ConfigError`; the third catches
everything else raised while wiring the broker. All three exit **2**.

```bash
nautilus serve --config /nonexistent/nautilus.yaml; echo "exit=$?"
```
