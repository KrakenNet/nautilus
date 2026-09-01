# Command line

## Conventions

Diagnostics go to **stderr** with a fixed prefix (`nautilus/cli/_common.py:88-101`):
`ERROR: `, `WARN: `, `FAIL: `. There are no Unicode sigils and no colour. `OK: ` marks
success.

Exit codes (`nautilus/cli/_common.py:5-7`): **0** success, **1** user error, **2**
validation/policy failure. Code **3** is deliberately never used.

Anything wrapped in `{…}` interpolates; `{exc}` is a lower-level error passed through unchanged.

## Any governance subcommand

### `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.`

`require_reviewer`, `nautilus/cli/_common.py:28-35`. Exit **1**.

**Means.** A command that records a governance decision has no operator identity to record. The
value comes from the environment only — there is no `$USER` auto-detection, because a reviewer
identity that the tool guesses is not evidence of anything.

**Fix.** `export NAUTILUS_REVIEWER="your.name@example.com"`.

```bash
env -u NAUTILUS_REVIEWER python - <<'PY'
from nautilus.cli._common import require_reviewer
try:
    require_reviewer()
except SystemExit as exc:
    print("exit code:", exc.code)
PY
```

## `nautilus serve`

`nautilus/cli/__init__.py:209-280` and `nautilus/cli/serve.py`. All of these exit **2**.

| Message | Line |
| --- | --- |
| `ERROR: config path does not exist or is not a file: {config_path}` | `__init__.py:210` |
| `ERROR: invalid config: {exc}` | `__init__.py:238` |
| `ERROR: broker construction failed: {exc}` | `__init__.py:241` |
| `ERROR: {exc}` (bind parsing, air-gapped load, serve failure) | `__init__.py:218,227,275` |

The wrapped `{exc}` texts:

### `--bind must be HOST:PORT, got {bind!r}`

**`ValueError`**, `nautilus/cli/serve.py:20-26`, printed as `ERROR: --bind must be HOST:PORT,
got 'badbind'`. Raised when the value has no `:` or an empty half.

### `--bind port must be an integer, got {port_s!r}`

`nautilus/cli/serve.py:27-29`.

### `Unable to read config '{config_path}': {exc}`

**`RuntimeError`**, `nautilus/cli/serve.py:123-125`, from the `--air-gapped` pre-pass that reads
the YAML before the broker does.

### `application startup failed; the server never accepted a connection. The cause is logged above.`

**`RuntimeError`**, `nautilus/cli/serve.py:162-166`. uvicorn returns from `serve()` rather than
raising when a lifespan fails, so without this the process exited **0** after never serving a
request. The real cause — a `ConfigError`, an unreachable session store — is in the log lines
directly above.

```bash
nautilus serve --config /nonexistent/nautilus.yaml; echo "exit=$?"
```

### `--air-gapped` warnings

`--air-gapped` strips anything that would leave the host. Each removal is announced on stderr
(`nautilus/cli/serve.py:60-105`); none is fatal.

| Message |
| --- |
| `WARN: --air-gapped drops LLM source id={…!r} — connection host is not loopback (NFR-1, #43)` |
| `WARN: --air-gapped overrides analysis.mode from {current_mode!r} to 'pattern' (NFR-1)` |
| `WARN: --air-gapped refuses analysis.provider (type={provider_type!r}); dropping it (NFR-1)` |

If a source you rely on is silently missing under `--air-gapped`, this is why.

## `nautilus health`

`nautilus/cli/health.py:15-28`. Exit **0** only on HTTP 200.

| Message | Line | Meaning |
| --- | --- | --- |
| `FAIL {status} {url}` | `:21` | The endpoint answered with a non-200 status. For `/readyz` the body carries the `reason` — see [transport.md](transport.md). |
| `FAIL {exc.code} {url}` | `:24` | An `HTTPError`: the code is `{exc.code}`. |
| `FAIL unreachable {url}: {exc}` | `:27` | The connection never completed. `{exc}` is the `URLError` — connection refused, DNS failure, timeout. |

```bash
nautilus health --url http://127.0.0.1:1/readyz; echo "exit=$?"
```

## `nautilus rules validate`

See [rules.md](rules.md) for `ERROR {file}:{line}: {message}` and
`ERROR: file not found: {file_path}`.

## `nautilus session version`

See [sessions.md](sessions.md).

## Argument parsing

An unknown subcommand or flag is handled by `argparse`, not by Nautilus, and exits **2**:

```text
usage: nautilus session [-h] subcommand ...
nautilus session: error: argument subcommand: invalid choice: 'schema' (choose from version)
```

`nautilus <command> --help` lists the valid subcommands for each group.

```bash
nautilus --help | head -25
```
