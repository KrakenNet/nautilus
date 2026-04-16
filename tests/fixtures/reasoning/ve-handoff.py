"""VE2b — :meth:`Broker.declare_handoff` two-agent caller (Task 5.3).

Builds a :class:`Broker` from the VE config, declares a ``secret``-class
handoff from ``orch-a`` (clearance=secret) to ``orch-b`` (clearance=cui),
and asserts:

1. :class:`HandoffDecision` returned with ``action == "deny"`` — the
   built-in ``information-flow-violation`` rule pack denies the cross-
   classification flow because ``orch-b``'s ``cui`` clearance does not
   dominate ``secret`` (FR-8, FR-10, AC-4.1, AC-4.3).
2. Exactly one new line appended to ``./ve-runtime/ve-audit.jsonl`` with
   nested ``event_type == "handoff_declared"`` (AC-4.4, NFR-15).

Lifecycle: explicit ``await broker.setup()`` for the Postgres-backed
session store, then ``await broker.aclose()`` twice to lock in the
Phase-1 close-idempotency contract (FR-17, AC-8.6).

Exit codes:
* 0 - all assertions passed; prints ``VE2b_HANDOFF_PASS``.
* 1 - any assertion failed; prints ``VE2b_HANDOFF_FAIL: <reason>``
  on stderr.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, cast

from nautilus.core.broker import Broker
from nautilus.core.models import HandoffDecision

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_PATH = _REPO_ROOT / "tests" / "fixtures" / "ve-config.yaml"
_AUDIT_PATH = _REPO_ROOT / "ve-runtime" / "ve-audit.jsonl"
_NAUTILUS_AUDIT_KEY = "nautilus_audit_entry"


def _count_audit_lines() -> int:
    """Return the number of non-empty lines in the VE audit JSONL."""
    if not _AUDIT_PATH.exists():
        return 0
    with _AUDIT_PATH.open("r", encoding="utf-8") as fh:
        return sum(1 for ln in fh if ln.strip())


def _read_last_audit_line() -> dict[str, Any]:
    """Return the parsed nested Nautilus AuditEntry from the last JSONL line."""
    raw_lines = [ln for ln in _AUDIT_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not raw_lines:
        raise AssertionError(f"audit file at {_AUDIT_PATH} contains no lines")
    outer = cast(dict[str, Any], json.loads(raw_lines[-1]))
    metadata = cast(dict[str, Any], outer.get("metadata") or {})
    nested_raw = metadata.get(_NAUTILUS_AUDIT_KEY)
    if not isinstance(nested_raw, str):
        raise AssertionError(
            f"last audit line missing metadata.{_NAUTILUS_AUDIT_KEY}; outer keys={list(outer)!r}"
        )
    return cast(dict[str, Any], json.loads(nested_raw))


def _wait_for_new_lines(before: int, expected_delta: int, timeout_s: float = 5.0) -> int:
    """Poll the audit file until ``count - before == expected_delta`` (or timeout)."""
    deadline = time.monotonic() + timeout_s
    after = _count_audit_lines()
    while time.monotonic() < deadline and (after - before) < expected_delta:
        time.sleep(0.1)
        after = _count_audit_lines()
    return after


async def _main() -> int:
    """Drive one declare_handoff call and run post-conditions; return exit code."""
    if not _CONFIG_PATH.is_file():
        print(f"VE2b_HANDOFF_FAIL: config not found at {_CONFIG_PATH}", file=sys.stderr)
        return 1

    missing = [k for k in ("VE_PG_DSN", "VE_API_KEY", "VE_ES_URL") if not os.environ.get(k)]
    if missing:
        print(f"VE2b_HANDOFF_FAIL: missing env vars: {missing}", file=sys.stderr)
        return 1

    audit_before = _count_audit_lines()

    broker = Broker.from_config(_CONFIG_PATH)
    await broker.setup()
    try:
        decision = await broker.declare_handoff(
            source_agent_id="orch-a",
            receiving_agent_id="orch-b",
            session_id="ve-handoff-1",
            data_classifications=["secret"],
        )
    finally:
        # Phase-1 close-idempotency lock-in (AC-8.6, FR-17): aclose() must
        # be safe to call repeatedly. Two consecutive awaits exercise the
        # ``self._closed`` short-circuit branch.
        await broker.aclose()
        await broker.aclose()

    if not isinstance(decision, HandoffDecision):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise AssertionError(f"declare_handoff did not return HandoffDecision: {type(decision)!r}")
    if decision.action != "deny":
        raise AssertionError(
            f"expected HandoffDecision.action='deny' (orch-b cui < secret); "
            f"got action={decision.action!r}, denials={decision.denial_records!r}"
        )
    if not decision.denial_records:
        raise AssertionError("deny decision missing denial_records (AC-4.3)")

    audit_after = _wait_for_new_lines(before=audit_before, expected_delta=1, timeout_s=5.0)
    delta = audit_after - audit_before
    if delta != 1:
        raise AssertionError(
            f"expected exactly 1 new audit line for 1 declare_handoff call (NFR-15); "
            f"got delta={delta} (before={audit_before}, after={audit_after})"
        )

    last = _read_last_audit_line()
    if last.get("event_type") != "handoff_declared":
        raise AssertionError(
            f"expected last audit event_type='handoff_declared' (AC-4.4); "
            f"got {last.get('event_type')!r}"
        )
    if last.get("session_id") != "ve-handoff-1":
        raise AssertionError(
            f"expected last audit session_id='ve-handoff-1'; got {last.get('session_id')!r}"
        )
    if last.get("handoff_id") != decision.handoff_id:
        raise AssertionError(
            f"audit handoff_id mismatch: audit={last.get('handoff_id')!r} "
            f"vs decision={decision.handoff_id!r}"
        )
    handoff_decision_payload = last.get("handoff_decision")
    if not isinstance(handoff_decision_payload, dict):
        raise AssertionError(
            f"audit handoff_decision missing/non-object: {handoff_decision_payload!r}"
        )
    if cast(dict[str, Any], handoff_decision_payload).get("action") != "deny":
        raise AssertionError(
            f"audit handoff_decision.action != 'deny': {handoff_decision_payload!r}"
        )

    print("VE2b_HANDOFF_PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(_main()))
    except AssertionError as exc:
        print(f"VE2b_HANDOFF_FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
