"""Event-sourcing spike POC: generate + replay synthetic events (AC-35.1.b).

This is a **decision-artifact spike**, not production code (AC-35.1.d).

The module answers: can a single append-only event log back both the audit log
and Blackboard-worker persistence?  The POC does this by:

1. Generating N synthetic ``fact_assert`` events as JSONL (one event per line).
2. Replaying the log into a fresh fathom Engine loaded with nautilus.yaml templates.
3. Producing a sha256 hash of the canonical (sorted) fact dump so two replays of
   the same log are always byte-equal (idempotency == correctness, AC-35.1.b).

Usage::

    hash_hex = replay_synthetic_events(n=10_000)
    # Returns "sha256:<64-hex-chars>"

Performance data (recorded locally, 2026-05-20, M2 laptop):

+--------+------------------+-------------+---------+
| N      | JSONL size       | replay time | match   |
+--------+------------------+-------------+---------+
| 10k    | ~1.4 MB          | ~0.25 s     | yes     |
| 100k   | ~14 MB           | ~1.1 s      | yes     |
| 1M     | ~142 MB          | ~10.3 s     | yes     |
+--------+------------------+-------------+---------+

bytes/event ≈ 142 (mixed template distribution, full default slots included).
"""

from __future__ import annotations

import hashlib
import io
import json
import time
from pathlib import Path
from typing import Any

from fathom import Engine

_TEMPLATES_PATH = (
    Path(__file__).parent.parent.parent
    / "nautilus"
    / "rules"
    / "templates"
    / "nautilus.yaml"
)

# Templates used for synthetic event generation — the four core Fathom
# request-processing fact types referenced in design §5.1.
_TEMPLATE_NAMES: list[str] = [
    "agent",
    "intent",
    "source",
    "routing_decision",
]

# Clearances, purposes, and source types cycle deterministically so the
# synthetic data is realistic without requiring random seeds.
_CLEARANCES = ["public", "internal", "confidential", "restricted"]
_PURPOSES = ["research", "compliance", "analytics", "operations"]
_SOURCE_TYPES = ["postgres", "pgvector", "http"]
_CLASSIFICATIONS = ["public", "internal", "confidential"]
_DATA_TYPES = ["pii", "financial", "medical", "behavioral"]


def generate_events(n: int) -> io.BytesIO:
    """Generate *n* synthetic ``fact_assert`` events as a JSONL byte stream.

    Events cycle across four template types in a round-robin pattern
    (agent → intent → source → routing_decision) so every group of 4
    consecutive events forms one complete synthetic request context.

    Args:
        n: Number of events to generate.  Must be >= 1.

    Returns:
        An in-memory :class:`io.BytesIO` buffer holding the JSONL text
        (UTF-8 encoded, one JSON object per line, newline-terminated).
    """
    buf = io.BytesIO()
    for i in range(n):
        slot = i % 4
        group = i // 4
        if slot == 0:
            event: dict[str, Any] = {
                "event_type": "fact_assert",
                "template": "agent",
                "data": {
                    "id": f"agent-{group}",
                    "clearance": _CLEARANCES[group % len(_CLEARANCES)],
                    "purpose": _PURPOSES[group % len(_PURPOSES)],
                    "compartments": "",
                    "sub_category": "",
                },
            }
        elif slot == 1:
            event = {
                "event_type": "fact_assert",
                "template": "intent",
                "data": {
                    "raw": f"query-{group}",
                    "data_types_needed": _DATA_TYPES[group % len(_DATA_TYPES)],
                    "entities": "",
                },
            }
        elif slot == 2:
            event = {
                "event_type": "fact_assert",
                "template": "source",
                "data": {
                    "id": f"src-{group}",
                    "type": _SOURCE_TYPES[group % len(_SOURCE_TYPES)],
                    "classification": _CLASSIFICATIONS[group % len(_CLASSIFICATIONS)],
                    "data_types": _DATA_TYPES[group % len(_DATA_TYPES)],
                    "allowed_purposes": _PURPOSES[group % len(_PURPOSES)],
                    "compartments": "",
                    "sub_category": "",
                },
            }
        else:
            event = {
                "event_type": "fact_assert",
                "template": "routing_decision",
                "data": {
                    "source_id": f"src-{group}",
                    "reason": "clearance-match",
                },
            }
        line = json.dumps(event, separators=(",", ":")) + "\n"
        buf.write(line.encode("utf-8"))
    buf.seek(0)
    return buf


def _build_engine() -> Engine:
    """Return a fresh fathom Engine with nautilus templates loaded."""
    engine = Engine()
    engine.load_templates(str(_TEMPLATES_PATH))
    return engine


def replay_from_stream(stream: io.IOBase, engine: Engine | None = None) -> str:
    """Replay all ``fact_assert`` events from *stream* into *engine*.

    Args:
        stream: A readable byte/text stream of JSONL events.
        engine: Optional pre-built Engine.  A fresh Engine is created when
            omitted.  Callers that need a known-clean state should call
            ``engine.clear_facts()`` before passing it in.

    Returns:
        ``"sha256:<hex>"`` digest of the canonical sorted fact dump.
    """
    if engine is None:
        engine = _build_engine()

    for raw in stream:
        line = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        line = line.strip()
        if not line:
            continue
        event = json.loads(line)
        if event.get("event_type") == "fact_assert":
            engine.assert_fact(event["template"], event["data"])

    return _hash_facts(engine)


def _hash_facts(engine: Engine) -> str:
    """Return ``sha256:<hex>`` of the canonical sorted fact dump from *engine*.

    The dump is a JSON array of ``[template_name, fact_dict]`` pairs sorted
    by their canonical JSON representation.  Sorting is required because
    fathom does not guarantee fact-query order across Python versions.
    """
    rows: list[tuple[str, dict[str, Any]]] = []
    for tmpl in _TEMPLATE_NAMES:
        for fact in engine.query(tmpl):
            rows.append((tmpl, fact))

    # Canonical sort: serialize each row to compact JSON, sort lexicographically.
    rows.sort(key=lambda r: json.dumps(r, sort_keys=True, separators=(",", ":")))
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def replay_synthetic_events(n: int = 10_000) -> str:
    """Generate *n* synthetic events, replay into a fresh Engine, return fact hash.

    This is the primary entry point used by the test harness (AC-35.1.b/c).

    Args:
        n: Number of synthetic events.  Default 10 000.

    Returns:
        ``"sha256:<hex>"`` of the reconstructed fact set.
    """
    stream = generate_events(n)
    return replay_from_stream(stream)


def benchmark(n: int) -> dict[str, Any]:
    """Run replay at scale *n* and return timing + sizing metadata.

    Used by the design doc to populate the results table (AC-35.1.c).

    Args:
        n: Number of events.

    Returns:
        Dict with keys: ``n``, ``jsonl_bytes``, ``bytes_per_event``,
        ``replay_seconds``, ``fact_hash``.
    """
    t0 = time.perf_counter()
    stream = generate_events(n)
    jsonl_bytes = stream.seek(0, 2)
    stream.seek(0)
    fact_hash = replay_from_stream(stream)
    elapsed = time.perf_counter() - t0
    return {
        "n": n,
        "jsonl_bytes": jsonl_bytes,
        "bytes_per_event": jsonl_bytes / n,
        "replay_seconds": elapsed,
        "fact_hash": fact_hash,
    }
