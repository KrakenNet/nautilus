# Attestation, keys and the chained log

Signing keys, the JWKS the broker publishes, and the hash-chained audit and attestation logs.
The chained log fails closed: if it cannot prove integrity, the broker stops rather than append
to something it cannot vouch for.

## Key management over HTTP

Both routes need the `keys` capability. `curl` examples assume the
[scratch broker](index.md#a-scratch-broker) on `127.0.0.1:8001` and
`export NAUTILUS=http://127.0.0.1:8001`.

| Message | Status | Line | Meaning |
| --- | --- | --- | --- |
| `reviewer is required (no control characters)` | 400 | `fastapi_app.py:1013` | `POST /v1/keys/rotate` needs `reviewer` in the body. Control characters are stripped, so a value made only of them reads as absent. |
| `reviewer and reason are required (no control characters)` | 400 | `fastapi_app.py:1059` | `POST /v1/keys/{kid}/revoke` needs both. |
| `kid must be a UUID` | 400 | `fastapi_app.py:1052` | The `{kid}` path segment is not a UUID. Take it from `/v1/keys/jwks.json`. |
| `kid {kid!r} not found` | 404 | `fastapi_app.py:1079` | No key with that id in the ring. |

```bash
curl -s -X POST "$NAUTILUS/v1/keys/rotate" \
  -H 'X-API-Key: govern-key' -H 'Content-Type: application/json' -d '{}'
curl -s -X POST "$NAUTILUS/v1/keys/not-a-uuid/revoke" \
  -H 'X-API-Key: govern-key' -H 'Content-Type: application/json' \
  -d '{"reviewer":"ops","reason":"test"}'
```

Rotation and revocation are also refused with **HTTP 409** carrying the underlying `ValueError`
text (`fastapi_app.py:1066-1074`) — most often:

### `kid {kid!r} is the current primary; rotate first, then revoke`

`nautilus/core/broker.py:1509`. Revoking the primary would leave nothing to sign with. Call
`POST /v1/keys/rotate` first, then revoke the now-superseded kid.

Both routes answer **503 `Key ring not ready`** (`fastapi_app.py:939`) when
`app.state.key_ring` is unset, and raise
`session tokens are disabled (session_tokens.enabled: false)` when tokens are off — see
[session-tokens.md](session-tokens.md).

## The key ring

### `Key {entry.kid!r} has no private key (revoked)`

**`ValueError`**, `nautilus/attestation/key_ring.py:259-262`. Something asked a revoked key to
sign. Private material is dropped on revocation, deliberately; only verification survives.

### `Expected Ed25519PrivateKey` / `Expected Ed25519PublicKey`

**`TypeError`**, `nautilus/attestation/key_ring.py:264` and `:273`. A PEM file at
`attestation.private_key_path` loaded successfully but is not Ed25519 — an RSA or EC key, or a
public key where a private one was expected. Nautilus signs with Ed25519 only.

### `attestation is disabled`

**`RuntimeError`**, `nautilus/core/broker.py:3140`. An attestation API was called while
`attestation.enabled` is false. Enable it, or stop calling that API.

## Chained log configuration

All raised at startup while building sinks.

### `attestation.sink.chained requires attestation.enabled with a signing key`

**`ValueError`**, `nautilus/core/broker.py:1074-1077`. A chained sink signs every line, so it
needs `attestation.enabled: true`.

### `audit.chained requires attestation.enabled with a signing key: each chained line carries a JWS, and there is nothing to sign with`

**`ValueError`**, `nautilus/audit/sink.py:57-62`. Same for the audit log. `build_audit_sink` is
the one place `audit.chained` becomes a sink, so the broker, the CLI's governance commands and
the rule-validation pipeline all fail here identically.

### `audit.chained cannot append to the existing chain at {audit_path} with an auto-generated signing key: attestation.private_key_path is unset, so this process signs with a key the lines already on disk were not signed by, and every request would fail closed on a log that reads as corrupt. Set attestation.private_key_path to the key that wrote them, or start a new chain at a new audit.path.`

**`ValueError`**, `nautilus/audit/sink.py:63-72`. The most common chained-log failure on a
second boot: the first run generated an ephemeral key, so the lines on disk cannot be extended.

**Fix.** Set `attestation.private_key_path` to a persistent key — before the first chained boot,
ideally — or point `audit.path` at a new file.

The warning that precedes it by one run (`nautilus/audit/sink.py:74-78`):

```text
audit.chained is on with an auto-generated attestation key: this chain is signed by this
process only and the next boot will refuse to append to it. Set attestation.private_key_path
to keep it.
```

## Single-writer enforcement

### `{subject} is already open for writing by {holder}. A hash chain admits exactly one writer: a second one interleaves into corruption that verify_chain cannot distinguish from tampering. {remedy}`

**`SinkAlreadyLockedError`** (`nautilus/core/attestation_sink.py:110`), raised by
`take_writer_lock` at `:131-135`.

**Interpolates.** `{subject}` — the chained file. `{holder}` — the process already holding it.
`{remedy}` — what to do, supplied by the caller.

**Means.** Two writers were pointed at one chained log — usually two brokers, but a CLI
governance command run beside a serving broker reaches the same lock and reports it as
[`ERROR: this decision cannot be recorded, so it will not be taken`](cli.md#error-this-decision-cannot-be-recorded-so-it-will-not-be-taken-problem).
`nautilus adapters schema-ack` reaches it too — it audits the override it records — and reports
it as [`ERROR: this acknowledgement cannot be recorded, so it will not be made`](cli.md#error-this-acknowledgement-cannot-be-recorded-so-it-will-not-be-made-problem).
Two interleaved writers produce a chain that fails verification identically to a tampered one,
so the second writer is refused.

**Fix.** Give each replica its own `audit.path` / `attestation.sink.path`, or run one writer.
The lock is an `flock`, which the kernel drops when the holder exits, so a leftover `<path>.lock`
file after a crash blocks nothing and does not need clearing.

### `emit on closed ChainedFileAttestationSink`

**`ValueError`**, `nautilus/core/attestation_sink.py:244`. A record was emitted after `close()`.
When embedding Nautilus, this means the broker was closed while work was still in flight — see
[library.md](library.md).

## Forensics offsets

`OffsetsCorruptError` (`nautilus/forensics/offsets.py:24`) — the resume file for the handoff
worker did not read back as it was written.

**What the caller sees, for all seven.** These have no HTTP route and no CLI command:
`nautilus/forensics/handoff_worker.py:217` calls `ProcessedOffsets.load()` and does not catch it,
and `run_worker` is a library entry point. The exception propagates to whatever process runs the
worker; a plain script exits **1** with a traceback ending in `OffsetsCorruptError: <message>`.
The audit log itself is untouched — nothing has been read yet when `load()` fails, and nothing has
been dropped when `save()` refuses.

The first six all mean the same thing operationally: the file was hand-edited, truncated, or
written by a different version. **Delete it** and the next run re-scans the audit log from byte 0.
That is safe — it re-reads, it does not re-emit, because the seen-hash set is rebuilt as it goes.

### `unreadable offsets file {path}: {exc}`

**`OffsetsCorruptError`**, `nautilus/forensics/offsets.py:75`. `{path}` is the offsets path as
given to `load()`; `{exc}` is the `OSError` or `json.JSONDecodeError` underneath, which carries the
line and column of the first bad byte.

**Means.** The file exists but could not be read or parsed as JSON. A truncated write from a killed
process is the common cause; the writer is atomic (temp file plus rename), so this normally means
something outside Nautilus touched it.

**Status.** Uncaught `OffsetsCorruptError` out of `run_worker` → exit **1** in a plain script.

**Fix.** `rm` the file.

```bash
python - <<'PY'
import pathlib, tempfile
from nautilus.forensics.offsets import ProcessedOffsets
p = pathlib.Path(tempfile.mkdtemp()) / "offsets.json"
p.write_text("{not json")
try:
    ProcessedOffsets.load(p)
except Exception as exc:
    print(f"{type(exc).__name__}: {str(exc).replace(str(p), 'offsets.json')}")
PY
```

```text
OffsetsCorruptError: unreadable offsets file offsets.json: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)
```

### `offsets payload must be a JSON object, got {type(payload).__name__}`

**`OffsetsCorruptError`**, `nautilus/forensics/offsets.py:78`. `{type(payload).__name__}` is the
Python type the JSON decoded to — `list`, `str`, `int`.

**Means.** The file parsed as JSON but the top level is not an object. The format is
`{"last_byte_offset": …, "seen_line_sha256": […]}`; a bare array is an older or foreign format.

**Status.** Uncaught → exit **1**.

**Fix.** Delete the file.

```bash
python - <<'PY'
import pathlib, tempfile
from nautilus.forensics.offsets import ProcessedOffsets
p = pathlib.Path(tempfile.mkdtemp()) / "offsets.json"
p.write_text("[1, 2]")
try:
    ProcessedOffsets.load(p)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
OffsetsCorruptError: offsets payload must be a JSON object, got list
```

### `last_byte_offset must be int, got {type(offset_raw).__name__}`

**`OffsetsCorruptError`**, `nautilus/forensics/offsets.py:85`. `{type(offset_raw).__name__}` is the
decoded type — `str`, `float`, `NoneType`, or `bool` (a JSON `true` is rejected here even though
`bool` is an `int` subclass in Python).

**Means.** The offset is fed to `file.seek()`. A string that happens to look numeric is not
coerced: `"512"` from a hand-edit and `512` from the writer are different values, and guessing
which one was meant risks re-reading or skipping audit lines.

**Status.** Uncaught → exit **1**.

**Fix.** Delete the file.

```bash
python - <<'PY'
import pathlib, tempfile
from nautilus.forensics.offsets import ProcessedOffsets
p = pathlib.Path(tempfile.mkdtemp()) / "offsets.json"
p.write_text('{"last_byte_offset": "512"}')
try:
    ProcessedOffsets.load(p)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
OffsetsCorruptError: last_byte_offset must be int, got str
```

### `last_byte_offset must be non-negative, got {offset_raw}`

**`OffsetsCorruptError`**, `nautilus/forensics/offsets.py:89`. `{offset_raw}` is the offending
integer itself, printed with `str()`: `-1`.

**Means.** A negative seek target. Python's `seek()` would raise `OSError` from inside the read
loop, halfway through a scan; this catches it at load with a sentence that names the file's
problem.

**Status.** Uncaught → exit **1**.

**Fix.** Delete the file.

```bash
python - <<'PY'
import pathlib, tempfile
from nautilus.forensics.offsets import ProcessedOffsets
p = pathlib.Path(tempfile.mkdtemp()) / "offsets.json"
p.write_text('{"last_byte_offset": -1}')
try:
    ProcessedOffsets.load(p)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
OffsetsCorruptError: last_byte_offset must be non-negative, got -1
```

### `seen_line_sha256 must be list, got {type(seen_raw).__name__}`

**`OffsetsCorruptError`**, `nautilus/forensics/offsets.py:93`. `{type(seen_raw).__name__}` is the
decoded type — `dict`, `str`, `NoneType`.

**Means.** The seen-hash set is persisted as a JSON array (`sorted()` on save) and re-read as a
list. Anything else is a foreign format. A missing key is fine — it defaults to `[]`.

**Status.** Uncaught → exit **1**.

**Fix.** Delete the file.

```bash
python - <<'PY'
import pathlib, tempfile
from nautilus.forensics.offsets import ProcessedOffsets
p = pathlib.Path(tempfile.mkdtemp()) / "offsets.json"
p.write_text('{"seen_line_sha256": {}}')
try:
    ProcessedOffsets.load(p)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
OffsetsCorruptError: seen_line_sha256 must be list, got dict
```

### `seen_line_sha256 entries must be str, got {type(item).__name__}`

**`OffsetsCorruptError`**, `nautilus/forensics/offsets.py:99`. `{type(item).__name__}` is the type
of the **first** non-string element; the scan stops there, so a file with several bad entries names
only the first.

**Means.** Every member of the set is a hex SHA-256 digest. A number or a nested object would be
compared against digests and never match, silently disabling the de-duplication that stops a
restart from re-emitting handoffs.

**Status.** Uncaught → exit **1**.

**Fix.** Delete the file.

```bash
python - <<'PY'
import pathlib, tempfile
from nautilus.forensics.offsets import ProcessedOffsets
p = pathlib.Path(tempfile.mkdtemp()) / "offsets.json"
p.write_text('{"seen_line_sha256": [1]}')
try:
    ProcessedOffsets.load(p)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
OffsetsCorruptError: seen_line_sha256 entries must be str, got int
```

### `refusing non-monotonic save: current={self.last_byte_offset} < persisted={existing.last_byte_offset}`

**`OffsetsCorruptError`**, `nautilus/forensics/offsets.py:120`, from `save()` — the only one of the
seven that is not a load failure. `{self.last_byte_offset}` is the offset the worker tried to
write; `{existing.last_byte_offset}` is the one already on disk.

**Means.** The worker tried to save an offset *behind* the persisted one, which on the next run
would re-read audit lines that have already been processed and re-emit their inferred handoffs. It
is refused and the persisted value stands — the save is a no-op, not a partial write.

**Deleting the file is the wrong fix here.** Two workers on one offsets path is the usual cause;
run one. The legitimate regression is log rotation, and the worker already handles it:
`_process_segment` (`handoff_worker.py:222-234`) detects `last_byte_offset > file size`, WARNs
`handoff_worker: audit file truncated or rotated …`, and `_persist_offsets`
(`handoff_worker.py:308-324`) unlinks the stale file before writing the reset state.

**Status.** Uncaught `OffsetsCorruptError` out of `run_worker` → exit **1**. Everything the segment
produced *has already been emitted* to the sink at this point — the save is the last step — so a
retry without fixing the cause re-emits that segment.

**Fix.** Ensure a single worker per offsets path. If you are deliberately rewinding, unlink the
file first, exactly as `_persist_offsets` does.

```bash
python - <<'PY'
import pathlib, tempfile
from nautilus.forensics.offsets import ProcessedOffsets
p = pathlib.Path(tempfile.mkdtemp()) / "offsets.json"
ProcessedOffsets(last_byte_offset=4096).save(p)
try:
    ProcessedOffsets(last_byte_offset=1024).save(p)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
print("persisted still:", ProcessedOffsets.load(p).last_byte_offset)
PY
```

```text
OffsetsCorruptError: refusing non-monotonic save: current=1024 < persisted=4096
persisted still: 4096
```

## Audit records

### `AuditRecord has no {NAUTILUS_METADATA_KEY!r} metadata`

**`KeyError`**, `nautilus/audit/logger.py:328`. A record was read that carries no Nautilus
metadata block. It came from a different writer, or the log mixes sources. Check that
`audit.path` is not shared with another tool.

## Offline verification

`nautilus attestation verify` checks a chained log without a running broker: link hashes,
per-line JWS signatures, and optionally an out-of-band head hash and checkpoint token.

```bash
nautilus attestation verify --help | head -20
```

Failures are reported by the command's own output rather than as exceptions; `--json` gives a
machine-readable verdict. `--expected-head` fails when the mirrored line hash is absent, which is
how tail truncation is caught — a chain that has had lines removed from the end is internally
consistent and only an external witness can detect it.
