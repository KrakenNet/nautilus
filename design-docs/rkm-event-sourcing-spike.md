# RKM Event-Sourcing Spike

**Status:** Complete — Phase H spike (AC-35.1.a–d).
**Decision artifact only. No production wiring (AC-35.1.d).**

---

## Question

Can a single append-only event log back **both** the RKM audit log **and**
Blackboard-worker persistence?

---

## Method

1. **Generate** N synthetic `fact_assert` events as a JSONL stream. Each line
   is a JSON object `{event_type, template, data}` representing one fact
   assertion into the Fathom CLIPS environment. Events cycle across four
   template types: `agent`, `intent`, `source`, `routing_decision`.
2. **Replay** the stream into a fresh `fathom.Engine` loaded with
   `nautilus/rules/templates/nautilus.yaml` (the same templates used by
   `FathomRouter` in production).
3. **Hash** the reconstructed fact set: all facts queried per template, sorted
   by canonical JSON, then sha256 of the combined dump.
4. **Assert idempotency**: replay the same stream twice and confirm both
   hashes match (deterministic replay = correctness proof, AC-35.1.b).
5. **Measure** JSONL size and wall-clock replay time at 10k / 100k / 1M events.

**POC location:** `spikes/event_sourcing/replay.py`
**Test location:** `spikes/event-sourcing/test_replay.py`

---

## Results

| N       | JSONL size | bytes/event | replay time | hash match |
|---------|-----------|-------------|-------------|------------|
| 10 000  | 1.44 MB   | 151 B       | 0.26 s      | yes        |
| 100 000 | 14.5 MB   | 152 B       | 2.59 s      | yes        |
| 1 000 000 | 146 MB  | 153 B       | 28.6 s      | yes        |

*Measured 2026-05-20 on a development Linux machine (6-core Intel, 16 GB RAM).
Includes event generation + CLIPS replay + sha256 hashing.*

**Targets hit:** 10k < 5 s ✓, 100k < 30 s ✓. 1M is 28.6 s (well under the
5-minute limit documented as acceptable in AC-35.1.c).

---

## Recommendation

**Hybrid.** Use a single append-only JSONL event log, but separate audit events
from Blackboard-state events at the schema level via the `event_type` field.

Rationale:

- The POC demonstrates that CLIPS working memory is fully reconstructible from a
  JSONL replay in sub-second time at 10k scale (the expected per-session fact
  volume). This validates the core assumption.
- The existing `audit.jsonl` file already uses a compatible append-only pattern
  (see `nautilus/core/attestation_sink.py`). Unifying both concerns under one log
  avoids a second write path.
- However, audit events and Blackboard-state events have different retention
  and query requirements. The audit log is append-forever and queried by
  compliance tooling; Blackboard state is per-session and queried by the worker
  for crash recovery. Mixing them in one physical file at scale creates
  unnecessary I/O for each concern.
- **Hybrid approach**: one physical file per session for Blackboard state (named
  `blackboard-<session_id>.jsonl`), plus the existing global `audit.jsonl` for
  audit events. Both follow the same append-only `{event_type, ...}` schema,
  enabling a single reader/writer library and shared tooling.

---

## Proposed Schema (unified event format)

```json
{
  "schema_version": 1,
  "event_type": "fact_assert | fact_retract | session_start | session_end | audit_*",
  "session_id": "<uuid>",
  "agent_id": "<string | null>",
  "template": "<fathom-template-name | null>",
  "data": { "<slot>": "<value>" },
  "ts": "<ISO-8601 UTC>",
  "seq": 42
}
```

Fields:

| Field            | Required | Notes                                              |
|------------------|----------|----------------------------------------------------|
| `schema_version` | yes      | Integer; allows readers to handle future formats.  |
| `event_type`     | yes      | Discriminator. `fact_assert` / `fact_retract` are Blackboard events; `audit_*` mirrors existing `AuditEntry.event_type`. |
| `session_id`     | yes      | Groups all events for one request context.         |
| `agent_id`       | no       | Populated for agent-initiated events.              |
| `template`       | no       | Fathom template name; required for fact events.    |
| `data`           | no       | Slot map; required for fact events, omitted for markers. |
| `ts`             | yes      | ISO-8601 UTC timestamp. Writer stamps on append.   |
| `seq`            | yes      | Monotonic counter scoped to `session_id`. Enables gap detection and ordered replay. |

### Encoding notes

- Multislot fields (e.g. `compartments`, `data_types_needed`) are stored as
  space-separated strings, matching the existing `clips_encoding.py` convention.
- `data` values are always strings on the wire. The Fathom layer handles
  type coercion (integer, float, symbol) at assert time, as it does today.
- `schema_version` bump is required for any breaking change to `data` field
  structure. Additive field additions to `data` are backwards-compatible.

---

## Trade-offs

### Storage cost

At ~152 bytes/event and a typical request generating 10–50 facts, a Blackboard
log per session costs 1.5–7.6 kB. For 1M requests/day that is ~7 GB/day before
compression. JSONL compresses ~4:1 with gzip, bringing the floor to ~1.75 GB/day.
The existing audit log (one line per request) costs <1 kB/request. Combined,
event-sourcing adds roughly 7–10× storage vs. audit-only. This is acceptable if
crash-recovery is required; optional if sessions are short-lived.

### Replay time

Sub-second at 10k facts (≈50 requests × 200 facts each). 100k in 2.6s is
acceptable for a crash-recovery scenario where the worker replays the
in-flight session. 1M in 28s is a batch-analysis ceiling, not an online path.

### Schema evolution

Adding new templates or slots is backwards-compatible (existing events lack the
new slot; Fathom defaults fill in). Renaming or removing slots is a breaking
change requiring a `schema_version` bump and a migration reader. The
`fact_retract` event type provides "compaction": a log can be trimmed by
replaying assert/retract pairs and emitting only the net-present facts.

### Crash recovery

The gap between the last flushed event and the crash is the recovery window.
With synchronous JSONL appends, this window is one write (≤ one event).
Asynchronous buffering (e.g. 100-event batches) trades durability for throughput;
choose based on session value. The `seq` field enables gap detection: a reader
that sees `seq` jump from 41 to 43 knows event 42 was lost.

### Multi-writer safety

JSONL append is safe under POSIX `O_APPEND` for writes ≤ `PIPE_BUF` (~4 kB on
Linux). Events above 4 kB risk interleaving; the schema above keeps events small
(< 1 kB typical). For the global `audit.jsonl` with concurrent writers, this
holds. Per-session Blackboard logs have exactly one writer (the session worker)
and are safe unconditionally.

---

## Open questions for task #37 (Blackboard wiring)

1. **Retention policy**: should Blackboard logs be deleted on session end or
   archived for forensics? The audit log already answers this for audit events.
2. **Compaction**: implement a log-compaction step that replays and re-emits only
   live facts? Reduces replay time and storage after long sessions.
3. **Index**: for recovery at scale (> 10k sessions in flight), an index file
   mapping `session_id → file offset` avoids full-scan on the global audit log.
4. **Atomicity**: for multi-fact transactions (e.g. `assert_facts` batches),
   consider wrapping in `session_start`/`session_end` markers so partial writes
   are detectable.

---

## Non-goals (AC-35.1.d)

- No integration with the v1 broker or production code paths.
- No persistent storage backend (POC uses in-memory `io.BytesIO`).
- No auth or encryption on the event log (out of scope for spike).
