"""One pin per Wave C1 item — a response that says why, and a broker you can
open with ``with``.

Wave C is the adoption half of the readiness review, ordered by impact per
keystroke. C1 is the highest-leverage item in the whole review: the broker
computes a denial reason, a rule name and a rule trace for every request,
writes all three to the audit log, and returns none of them to the caller. An
agent is told *that* it was denied and has to go read a JSONL file on the
broker's host to find out why. C8 is the same complaint about lifecycle: every
example is a ``try/finally`` because there is no context manager.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.defect

_SOURCE: dict[str, Any] = {
    "id": "patients",
    "type": "postgres",
    "description": "patient records",
    "classification": "secret",
    "data_types": ["patients"],
    "allowed_purposes": ["care"],
    # Never reached: the pins below are all decided before any adapter connects.
    "connection": "postgresql://127.0.0.1:1/none",
    "table": "public.t",
}

# A second source the intent never asks for, so it is skipped rather than denied.
_UNRELATED: dict[str, Any] = {
    **_SOURCE,
    "id": "invoices",
    "data_types": ["invoices"],
    # Unclassified, so it is skipped for having nothing to do with the intent
    # rather than denied for outranking the agent.
    "classification": "unclassified",
}


def _config(tmp_path: Path, **overrides: Any) -> str:
    config: dict[str, Any] = {
        "sources": [_SOURCE, _UNRELATED],
        "agents": {"intern": {"id": "intern", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "rules": {"packs": [], "user_rules_dirs": []},
    }
    config.update(overrides)
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return str(path)


def _ask(config_path: str) -> Any:
    from nautilus.core.broker import Broker

    broker = Broker.from_config(config_path)
    try:
        return broker.request("intern", "patients", {"purpose": "care"})
    finally:
        broker.close()


# ===========================================================================
# C1 -- the denial reason exists, is signed, is logged, and never returned
# ===========================================================================


def test_c1_a_denied_source_tells_the_caller_why(tmp_path: Path) -> None:
    """``sources_denied`` is a list of ids and nothing else.

    The router produced a ``DenialRecord`` with a reason and the rule that
    fired; the audit entry has both. The caller — the agent that has to decide
    what to do next — gets an id.
    """
    response = _ask(_config(tmp_path))

    assert response.sources_denied == ["patients"], response.sources_denied
    denials = {d.source_id: d for d in response.denial_records}
    assert "patients" in denials, (
        f"the response carries no denial record for the source it denied: {response.denial_records}"
    )
    assert denials["patients"].reason, "the denial record has no reason"
    assert denials["patients"].rule_name, "the denial record does not name the rule that denied"


def test_c1_the_response_carries_the_same_rule_trace_the_audit_entry_does(
    tmp_path: Path,
) -> None:
    """The trace is what makes a decision explainable, and only the operator sees it.

    Control against inventing a second trace: the response's trace must be the
    one that was recorded, not a re-derived approximation.
    """
    from fathom.models import AuditRecord

    from nautilus.audit.logger import decode_nautilus_entry

    audit_path = tmp_path / "audit.jsonl"
    response = _ask(_config(tmp_path))

    entries = [
        decode_nautilus_entry(AuditRecord.model_validate(json.loads(line)))
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    logged = next(e for e in entries if e.event_type == "request")
    assert response.rule_trace, "the response carries no rule trace"
    assert response.rule_trace == logged.rule_trace, (
        f"the response trace {response.rule_trace} is not the logged trace {logged.rule_trace}"
    )


def test_c1_a_skipped_source_says_why_it_was_skipped(tmp_path: Path) -> None:
    """``sources_skipped`` appears in zero docs and carries zero explanation.

    A source is skipped when no routing decision selected it and nothing
    denied it — almost always because its data types have nothing to do with
    the intent. That is a diagnosable answer, and the caller gets an id.
    """
    response = _ask(_config(tmp_path))

    assert response.sources_skipped == ["invoices"], response.sources_skipped
    skips = {s.source_id: s.reason for s in response.skip_records}
    assert "invoices" in skips, f"no skip record for the skipped source: {response.skip_records}"
    assert "invoices" in skips["invoices"] or "data type" in skips["invoices"].lower(), (
        f"the skip reason does not say why: {skips['invoices']!r}"
    )


def test_c1_an_answered_request_carries_no_denial_or_skip_noise(tmp_path: Path) -> None:
    """Control: the new fields must be empty when nothing was denied or skipped."""
    config = _config(
        tmp_path,
        sources=[{**_SOURCE, "classification": "unclassified"}],
    )
    response = _ask(config)

    # The source is routed (its adapter then fails to connect, which is not
    # what this pin is about): nothing was denied and nothing was skipped.
    assert response.sources_denied == [], response.sources_denied
    assert response.sources_skipped == [], response.sources_skipped
    assert response.denial_records == [], response.denial_records
    assert response.skip_records == [], response.skip_records


# ===========================================================================
# C8 -- the lifecycle every example has to spell out by hand
# ===========================================================================


def test_c8_the_broker_is_a_context_manager(tmp_path: Path) -> None:
    """Every doc example is a ``try/finally`` because there is no ``with``.

    And the ``finally`` is load-bearing: ``close()`` refuses to run inside a
    running loop, so the sync and async forms are genuinely different and both
    have to exist.
    """
    from nautilus.core.broker import Broker

    config = _config(tmp_path)

    with Broker.from_config(config) as broker:
        response = broker.request("intern", "patients", {"purpose": "care"})
        assert response.request_id
    assert broker.closed, "the sync context manager did not close the broker"

    async def _async_form() -> Any:
        async with await Broker.afrom_config(config) as broker:
            await broker.arequest("intern", "patients", {"purpose": "care"})
            return broker

    async_broker = asyncio.run(_async_form())
    assert async_broker.closed, "the async context manager did not close the broker"


def test_c8_the_response_says_what_happened_in_one_word(tmp_path: Path) -> None:
    """Reading the outcome means comparing four lists in the right order.

    The audit log already derives exactly this word for every entry; the
    caller has to re-derive it, and getting the precedence wrong is the
    difference between "nothing matched" and "you were refused".
    """
    denied = _ask(_config(tmp_path))
    assert denied.outcome == "denied", denied.outcome

    # Routed, then the adapter could not connect: an error, not a refusal.
    errored = _ask(_config(tmp_path, sources=[{**_SOURCE, "classification": "unclassified"}]))
    assert errored.outcome == "errored", errored.outcome
