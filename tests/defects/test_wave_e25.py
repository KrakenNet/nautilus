"""WAVE E25 -- turning the integrity guarantee on breaks the product.

``audit.chained: true`` is the deployment's tamper-evidence: every audit line
carries ``prev_sha256`` linkage and a JWS, so a deleted or edited line is
detectable offline. Two shipped paths were written against the unchained shape
and never learned about the envelope:

- ``POST /v1/rkm/queue`` built its own ``AuditLogger(sink=FileSink(...))`` over
  the configured ``audit.path`` and appended two plain ``AuditRecord`` lines
  into the middle of the chain. ``verify_chain`` then reports ``malformed line
  N`` for the life of that file -- offline verification is dead, permanently,
  and the record of what was decided can no longer be shown to be intact.
- Every reader validated each line as a plain record, so a chained log read
  back as one corrupt line per entry: ``GET /v1/audit`` returned no entries,
  ``GET /v1/audit/{request_id}`` 404'd, and the sandbox replay that scores
  every rule proposal saw an empty corpus.

The pins run against the real app built from a real ``nautilus.yaml`` with
chaining on, and verify the log with fathom's offline verifier against the
public key exported beside it -- the same two things an operator does.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.defect

_SOURCE: dict[str, Any] = {
    "id": "src",
    "type": "postgres",
    "description": "a source",
    "classification": "unclassified",
    "data_types": ["patients"],
    "allowed_purposes": ["care"],
    # Never connected to: the request is decided, audited and answered whether
    # or not the adapter can reach anything.
    "connection": "postgresql://127.0.0.1:1/none",
    "table": "public.t",
}

_PROPOSED_RULE = """
module: nautilus-routing
ruleset: wave-e25-proposal
version: "1.0"
rules:
  - name: e25-deny-secret
    description: "Deny secret sources."
    salience: 160
    when:
      - template: source
        conditions:
          - slot: id
            bind: ?sid
          - slot: classification
            equals: secret
    then:
      action: deny
      reason: "e25"
      assert:
        - template: denial_record
          slots:
            source_id: "?sid"
            reason: "e25"
            rule_name: "e25-deny-secret"
"""


def _config(tmp_path: Path, **overrides: Any) -> str:
    """Write a loadable ``nautilus.yaml`` with a chained audit log.

    The signing key is on disk, which is what a deployment that chains its
    audit log has to do: an auto-generated key lives and dies with one process,
    and the broker itself warns that the next boot will refuse to append.
    """
    from fathom.chained_log import load_or_create_key

    key_path = tmp_path / "attestation-key.pem"
    load_or_create_key(key_path)
    config: dict[str, Any] = {
        "sources": [_SOURCE],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl"), "chained": True},
        "attestation": {"enabled": True, "private_key_path": str(key_path)},
        "rules": {"packs": [], "user_rules_dirs": []},
        "api": {"keys": ["k"]},
    }
    config.update(overrides)
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return str(path)


def _app(config_path: str, tmp_path: Path) -> Any:
    """The real app, with the RKM stores pointed away from the repo."""
    from nautilus.rkm.lineage import LineageStore
    from nautilus.rkm.queue import ProposalQueue
    from nautilus.transport.fastapi_app import create_app

    app = create_app(config_path)
    app.state.proposal_queue = ProposalQueue(tmp_path / "queue")
    app.state.lineage_store = LineageStore(tmp_path / "lineage")
    return app


def _ask(client: Any) -> Any:
    return client.post(
        "/v1/request",
        headers={"X-API-Key": "k"},
        json={
            "agent_id": "analyst",
            "intent": "patients",
            "context": {"purpose": "care"},
        },
    )


def _verify(audit_path: Path) -> Any:
    """Offline verification, exactly as an operator runs it."""
    from fathom.chained_log import verify_chain

    return verify_chain(audit_path, audit_path.with_name(audit_path.name + ".pub.pem"))


# ===========================================================================
# E25a -- POST /v1/rkm/queue permanently corrupts a chained audit log
# ===========================================================================


def test_e25a_an_rkm_submission_leaves_the_audit_chain_verifiable(tmp_path: Path) -> None:
    """The queue route's two governance events must join the chain, not break it.

    ``run_pipeline`` opened ``FileSink(audit_log)`` directly -- the one audit
    sink construction in the tree that never asked ``audit.chained`` -- so
    ``proposal_emitted`` and ``proposal_validated`` landed as bare records
    between two chained lines. The damage is not recoverable: the plain lines
    have no ``prev_sha256`` to repair from.
    """
    from fastapi.testclient import TestClient

    audit_path = tmp_path / "audit.jsonl"
    with TestClient(_app(_config(tmp_path), tmp_path)) as client:
        assert _ask(client).status_code == 200
        before = _verify(audit_path)
        assert before.ok, f"the chain was already broken before the submission: {before.error}"

        submitted = client.post(
            "/v1/rkm/queue",
            headers={"X-API-Key": "k"},
            json={"rule_yaml": _PROPOSED_RULE},
        )
        assert submitted.status_code == 201, submitted.text

    after = _verify(audit_path)
    assert after.ok, (
        f"one rule submission destroyed offline verification of the audit log: "
        f"{after.error} (line {after.error_line}). The chain verified before the "
        f"POST and does not after; no later write can repair it."
    )
    assert after.count > before.count, (
        "the submission verified but recorded nothing: proposal_emitted and "
        "proposal_validated must still reach the log"
    )


def test_e25a_the_submitted_governance_events_are_readable_back(tmp_path: Path) -> None:
    """Control for the pin above: an intact chain that recorded nothing is no fix.

    Dropping the two events would leave ``verify_chain`` green and the
    governance record silent about who proposed what. This passed before the
    fix for a reason worth stating: the two unchained lines the pipeline wrote
    were the *only* ones the audit API could read, because they were the only
    ones not in the envelope it did not understand.
    """
    from fastapi.testclient import TestClient

    with TestClient(_app(_config(tmp_path), tmp_path)) as client:
        submitted = client.post(
            "/v1/rkm/queue",
            headers={"X-API-Key": "k"},
            json={"rule_yaml": _PROPOSED_RULE},
        )
        assert submitted.status_code == 201, submitted.text
        proposal_id = submitted.json()["proposal_id"]

        listed = client.get(
            "/v1/audit",
            headers={"X-API-Key": "k"},
            params={"limit": 100},
        )
        assert listed.status_code == 200, listed.text
        events = {
            e["event_type"]: e
            for e in listed.json()["entries"]
            if e.get("event_type") in {"proposal_emitted", "proposal_validated"}
        }
    assert set(events) == {"proposal_emitted", "proposal_validated"}, (
        f"the queue route's governance events did not come back through the "
        f"audit API: {sorted(events)}"
    )
    assert events["proposal_emitted"]["event_fields"]["proposal_id"] == proposal_id


# ===========================================================================
# E25b -- audit.chained: true silently empties the audit query API
# ===========================================================================


def test_e25b_the_audit_api_returns_entries_when_the_log_is_chained(tmp_path: Path) -> None:
    """``GET /v1/audit`` must read the log the deployment actually writes.

    ``AuditReader._parse_line`` validated every line as a plain fathom
    ``AuditRecord``. A chained line is an envelope around one, so every line
    failed and was swallowed by a ``warning`` -- the API answered
    ``{"entries": []}`` over a full, intact log.
    """
    from fastapi.testclient import TestClient

    with TestClient(_app(_config(tmp_path), tmp_path)) as client:
        answered = _ask(client)
        assert answered.status_code == 200
        request_id = answered.json()["request_id"]

        listed = client.get("/v1/audit", headers={"X-API-Key": "k"})
        assert listed.status_code == 200, listed.text
        entries = listed.json()["entries"]
        assert entries, (
            "the audit API reported no entries over a chained log that has "
            "them: every line was discarded as corrupt"
        )
        assert request_id in [e["request_id"] for e in entries]

        shown = client.get(f"/v1/audit/{request_id}", headers={"X-API-Key": "k"})
        assert shown.status_code == 200, (
            f"the audit lookup 404'd on a request the chained log recorded: {shown.text}"
        )
        assert shown.json()["request_id"] == request_id


def test_e25b_a_genuinely_unreadable_line_is_still_reported(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Understanding the envelope must not turn the reader into a mute.

    A torn write is a different failure from a line whose shape the reader has
    no entry in -- fathom's own genesis and checkpoint records are the latter
    and are not corruption. The first must still be logged; the second must
    not cry wolf once per line per read.
    """
    from fastapi.testclient import TestClient

    from nautilus.ui.audit_reader import AuditReader

    audit_path = tmp_path / "audit.jsonl"
    with TestClient(_app(_config(tmp_path), tmp_path)) as client:
        assert _ask(client).status_code == 200

    lines = audit_path.read_text(encoding="utf-8").splitlines()
    lines.append('{"seq": 99, "not": "a chain line"')  # torn: unparseable JSON
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="nautilus.ui.audit_reader"):
        page = AuditReader(audit_path).read_page()

    assert page.entries, "the readable lines must still come back"
    warnings = [r.getMessage() for r in caplog.records if r.name == "nautilus.ui.audit_reader"]
    assert len(warnings) == 1, (
        f"expected exactly one warning -- for the torn line, and none for the "
        f"chain's own genesis record -- got {warnings}"
    )
    assert "corrupt" in warnings[0]


# ===========================================================================
# E25c -- the sandbox scores every proposal against an empty corpus
# ===========================================================================


def test_e25c_the_sandbox_replays_a_chained_audit_log(tmp_path: Path) -> None:
    """The replay corpus is read from the same file the broker chains.

    ``_load_entries`` reached for ``metadata`` at the top level of each line,
    which on a chained log is inside ``record``. Every proposal therefore
    replayed against zero recorded requests and scored as
    ``insufficient_history`` regardless of what it did.
    """
    from fastapi.testclient import TestClient

    from nautilus.rkm.validator.sandbox import (
        _load_entries,  # noqa: PLC2701  # pyright: ignore[reportPrivateUsage]
    )

    audit_path = tmp_path / "audit.jsonl"
    with TestClient(_app(_config(tmp_path), tmp_path)) as client:
        for _ in range(3):
            assert _ask(client).status_code == 200

    entries = _load_entries(audit_path, 100)
    assert len([e for e in entries if e.event_type == "request"]) == 3, (
        f"the sandbox read {len(entries)} entries out of a chained log holding "
        f"three requests; every proposal scores against an empty corpus"
    )


# ===========================================================================
# E25d -- the CLI's governance decisions corrupt the same chain
# ===========================================================================


def test_e25d_a_cli_governance_decision_keeps_the_chain_verifiable(tmp_path: Path) -> None:
    """``open_audit_logger`` is the third sink construction, with the same bug.

    ``rule approve`` / ``reject`` / ``retract`` / ``rollback`` all record their
    decision through it, and it opened a plain ``FileSink`` over the config's
    ``audit.path`` -- so a governance decision taken from the CLI corrupted a
    chained log exactly the way the queue route did.
    """
    from fastapi.testclient import TestClient

    from nautilus.cli._common import open_audit_logger

    config_path = _config(tmp_path)
    audit_path = tmp_path / "audit.jsonl"
    # The chain has to exist first: a governance decision is taken against a
    # deployment that has been running.
    with TestClient(_app(config_path, tmp_path)) as client:
        assert _ask(client).status_code == 200

    logger = open_audit_logger(config_path)
    logger.emit_event({"event_type": "proposal_approved", "proposal_id": "p1", "reviewer": "rev-1"})
    close = getattr(logger.sink, "close", None)
    if close is not None:
        close()

    result = _verify(audit_path)
    assert result.ok, (
        f"a CLI governance decision broke the chain: {result.error} (line {result.error_line})"
    )


def test_e25d_a_cli_decision_refuses_a_chain_it_cannot_sign(tmp_path: Path) -> None:
    """Control: the fix must be a refusal, never a best-effort plain line.

    With ``attestation.private_key_path`` unset the broker generates a keypair
    that lives and dies with its process, so a CLI run has no key the existing
    lines were signed with. Signing anyway would produce a log no single public
    key verifies -- the same permanent damage by another route.
    """
    config_path = _config(tmp_path, attestation={"enabled": True})
    with pytest.raises(ValueError, match="audit.chained"):
        from nautilus.cli._common import open_audit_logger

        open_audit_logger(config_path)


def test_e25d_a_cli_decision_is_refused_before_it_is_taken(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A decision that cannot be recorded must not be taken.

    A chain admits one writer, so a CLI governance command run against a live
    server cannot append. ``SingleWriterAuditSink`` claims the lock at the
    first write, and ``review.approve`` writes *after* it has promoted the
    rule and inserted the lineage row -- a rule in force with nothing in the
    log saying who put it there. ``open_audit_logger`` claims the lock up
    front so the refusal lands before anything is decided.
    """
    from fastapi.testclient import TestClient

    from nautilus.cli._common import open_audit_logger

    config_path = _config(tmp_path)
    with TestClient(_app(config_path, tmp_path)) as client:
        assert _ask(client).status_code == 200

        with pytest.raises(SystemExit) as exited:
            open_audit_logger(config_path)

    assert exited.value.code == 2
    message = capsys.readouterr().err
    assert "will not be taken" in message, message
    assert "governance API" in message, message
