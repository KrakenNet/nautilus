"""One pin per Wave B3 item — the operational surface of a running deployment.

Wave B3 is the §3 work of the readiness review: the things an operator needs
once Nautilus is actually serving. An empty ``agents:`` block silently means
"the caller declares its own clearance"; retraction and rollback are billed
destructive and never touch the running engine; there is no way to ask which
rules are in force; the audit log has no integrity option at any setting; a
caller-supplied ``scope_constraints`` typo is a 500; ``/readyz`` never probes
the one dependency whose failure 500s every request; and a config error prints
resolved secrets to stderr.

Each pin drives the surface a deployment presents — the REST app built from a
real ``nautilus.yaml``, or the broker as a library.
"""

from __future__ import annotations

import json
import logging
import stat
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
    "allowed_purposes": ["care", "b3-probe"],
    # Never reached: every pin here is decided before any adapter connects.
    "connection": "postgresql://127.0.0.1:1/none",
    "table": "public.t",
}

# A user rule that denies every source for one purpose only, so the control
# (a request under another purpose) stays unaffected by it.
_PROBE_RULE = """
module: nautilus-routing
ruleset: wave-b3-retract
version: "1.0"
rules:
  - name: wave-b3-probe-deny
    description: "Deny every source for the retract pin's purpose."
    salience: 300
    when:
      - template: agent
        conditions:
          - slot: purpose
            bind: ?purpose
          - test: '(eq ?purpose "b3-probe")'
      - template: source
        conditions:
          - slot: id
            bind: ?sid
    then:
      action: deny
      reason: "wave-b3 retract probe"
      assert:
        - template: denial_record
          slots:
            source_id: "?sid"
            reason: "wave-b3 retract probe"
            rule_name: "wave-b3-probe-deny"
"""


def _config(tmp_path: Path, **overrides: Any) -> str:
    """Write a loadable ``nautilus.yaml`` and return its path."""
    config: dict[str, Any] = {
        "sources": [_SOURCE],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "rules": {"packs": [], "user_rules_dirs": []},
        "api": {"keys": ["k"]},
    }
    config.update(overrides)
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return str(path)


def _client(config_path: str, **client_kwargs: Any) -> Any:
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    return TestClient(create_app(config_path), **client_kwargs)


def _ask(client: Any, purpose: str = "care", **context: Any) -> Any:
    return client.post(
        "/v1/request",
        headers={"X-API-Key": "k"},
        json={
            "agent_id": "analyst",
            "intent": "patients",
            "context": {"purpose": purpose, **context},
        },
    )


# ===========================================================================
# B3a -- an empty agents: block is caller-declares-clearance, in silence
# ===========================================================================


def test_b3a_a_config_with_no_agents_says_the_caller_declares_its_own_clearance(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """No ``agents:`` block means every attribute comes from the caller.

    ``_resolve_agent`` returns ``None`` for an empty registry and the router
    then reads ``context["clearance"]`` — so a request can name its own
    clearance and read anything. That is a defensible bootstrap default, and
    getting-started teaches exactly that shape, but it is the single largest
    posture difference between a demo and a deployment and nothing says it.
    """
    from nautilus.core.broker import Broker

    config = _config(tmp_path, agents={})
    with caplog.at_level(logging.WARNING):
        broker = Broker.from_config(config)
    try:
        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("clearance" in m for m in warnings), (
            f"a config with no agents: started silently; warnings were {warnings}"
        )
    finally:
        broker.close()


def test_b3a_a_config_that_declares_agents_starts_quietly(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Control: the warning must be about the empty registry, not about startup.

    Without this the pin above would pass on a broker that warned every time.
    """
    from nautilus.core.broker import Broker

    with caplog.at_level(logging.WARNING):
        broker = Broker.from_config(_config(tmp_path))
    try:
        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert not any("clearance" in m for m in warnings), (
            f"a config that declares agents warned about clearance anyway: {warnings}"
        )
    finally:
        broker.close()


# ===========================================================================
# B3b -- retract and rollback are billed destructive and change nothing
# ===========================================================================


def _lineage_seed(base_dir: Path, rule_name: str) -> None:
    """Give ``rule_name`` a lineage record so the retract route can find it."""
    from datetime import UTC, datetime

    from nautilus.rkm.lineage import LineageRecord, LineageStore

    store = LineageStore(base_dir / ".nautilus" / "rkm" / "lineage")
    store.insert(
        LineageRecord(
            rule_name=rule_name,
            version=1,
            proposer="pin",
            observation_ids={},
            sandbox_results={},
            approver="pin",
            derived_from=(),
            promoted_at=datetime.now(UTC),
            module="nautilus-routing",
        )
    )


def _rules_config(tmp_path: Path) -> str:
    user_rules = tmp_path / "user-rules"
    user_rules.mkdir()
    (user_rules / "probe.yaml").write_text(_PROBE_RULE, encoding="utf-8")
    return _config(tmp_path, rules={"packs": [], "user_rules_dirs": [str(user_rules)]})


def test_b3b_retracting_a_rule_stops_it_firing_in_the_running_engine(tmp_path: Path) -> None:
    """``POST /v1/rules/{name}/retract`` only writes lineage.

    The route is gated on ``yes=true`` "for a destructive operation", emits a
    ``rule_retracted`` audit event, and returns the affected descendants — and
    the rule keeps firing on every subsequent request until someone restarts
    the broker, which no part of the response or the docs says.
    """
    config = _rules_config(tmp_path)
    _lineage_seed(tmp_path, "wave-b3-probe-deny")
    with _client(config) as client:
        client.app.state.lineage_store = None  # resolved lazily below
        from nautilus.rkm.lineage import LineageStore

        client.app.state.lineage_store = LineageStore(tmp_path / ".nautilus" / "rkm" / "lineage")

        before = _ask(client, purpose="b3-probe")
        assert before.status_code == 200, before.text
        assert before.json()["sources_denied"], (
            "the probe rule did not deny anything before retraction, so this pin "
            "would pass on an engine that never loaded it"
        )

        retracted = client.post(
            "/v1/rules/wave-b3-probe-deny/retract",
            headers={"X-API-Key": "k", "X-Nautilus-Reviewer": "pin"},
            json={"yes": True, "reason": "pin"},
        )
        assert retracted.status_code == 200, retracted.text

        after = _ask(client, purpose="b3-probe")
        assert after.status_code == 200, after.text
        assert not after.json()["sources_denied"], (
            "the retracted rule is still denying sources in the running engine"
        )


def test_b3b_a_retraction_says_whether_the_engine_changed(tmp_path: Path) -> None:
    """A rule in lineage but not in force must not report a live retraction.

    Control for the pin above: the response has to distinguish "removed from
    the engine" from "marked retired in the ledger", or an operator cannot
    tell whether the rule is still deciding requests.
    """
    config = _config(tmp_path)
    _lineage_seed(tmp_path, "never-loaded-rule")
    with _client(config) as client:
        from nautilus.rkm.lineage import LineageStore

        client.app.state.lineage_store = LineageStore(tmp_path / ".nautilus" / "rkm" / "lineage")
        response = client.post(
            "/v1/rules/never-loaded-rule/retract",
            headers={"X-API-Key": "k", "X-Nautilus-Reviewer": "pin"},
            json={"yes": True, "reason": "pin"},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body.get("engine_updated") is False, (
            f"a rule that was never in force reported a live retraction: {body}"
        )


def test_b3b_a_rollback_does_not_claim_the_engine_followed_it(tmp_path: Path) -> None:
    """Rollback re-promotes a lineage version and never reloads any rule text.

    The lineage record carries no rule YAML, so there is nothing to reload; the
    honest response says so rather than reading as a completed deploy.
    """
    config = _config(tmp_path)
    _lineage_seed(tmp_path, "rollback-probe")
    with _client(config) as client:
        from nautilus.rkm.lineage import LineageStore

        client.app.state.lineage_store = LineageStore(tmp_path / ".nautilus" / "rkm" / "lineage")
        response = client.post(
            "/v1/rules/rollback-probe/rollback",
            headers={"X-API-Key": "k", "X-Nautilus-Reviewer": "pin"},
            json={"yes": True, "to_version": 1, "reason": "pin"},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body.get("engine_updated") is False, (
            f"rollback reported an engine change it never made: {body}"
        )
        assert body.get("engine_note"), (
            "rollback did not say what an operator must still do to make the restored version live"
        )


# ===========================================================================
# B3c -- no ruleset_hash, and no way to ask which rules are in force
# ===========================================================================


def test_b3c_the_rules_in_force_can_be_listed(tmp_path: Path) -> None:
    """Nothing answers "which rules is this broker deciding with?".

    The engine knows — ``rule_registry`` and ``ruleset_hash`` are both public
    on ``fathom.Engine`` — but no CLI, route or response surfaces either, so a
    deployment cannot be compared against the rules someone believes it runs.
    """
    with _client(_rules_config(tmp_path)) as client:
        response = client.get("/v1/rules", headers={"X-API-Key": "k"})
        assert response.status_code == 200, response.text
        body = response.json()
        names = [r["name"] for r in body["rules"]]
        assert "wave-b3-probe-deny" in names, f"the user rule is not listed: {names}"
        assert "default-classification-deny" in names, f"built-ins are not listed: {names}"
        assert body["ruleset_hash"].startswith("sha256:"), body


def test_b3c_listing_the_rules_in_force_requires_a_credential(tmp_path: Path) -> None:
    """Control: the rules in force describe the deployment's policy posture."""
    with _client(_config(tmp_path)) as client:
        assert client.get("/v1/rules").status_code == 401


def test_b3c_the_audit_entry_names_the_ruleset_that_decided(tmp_path: Path) -> None:
    """A decision is only reproducible against the rules that made it.

    The entry records ``rule_trace`` and ``fact_set_hash`` but not which
    ruleset was loaded, so replaying an entry against a changed deployment
    silently compares two different policies.
    """
    from fathom.models import AuditRecord

    from nautilus.audit.logger import decode_nautilus_entry

    audit_path = tmp_path / "audit.jsonl"
    with _client(_config(tmp_path)) as client:
        assert _ask(client).status_code == 200
        engine_hash = client.app.state.broker.ruleset_hash

    entries = [
        decode_nautilus_entry(AuditRecord.model_validate(json.loads(line)))
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    requests = [e for e in entries if e.event_type == "request"]
    assert requests, "no request entry was written"
    assert requests[0].ruleset_hash == engine_hash, (
        f"the audit entry records ruleset_hash={requests[0].ruleset_hash!r}, "
        f"the engine is running {engine_hash!r}"
    )


# ===========================================================================
# B3d -- the audit log has no integrity option at any setting
# ===========================================================================


def test_b3d_the_audit_log_can_be_hash_chained(tmp_path: Path) -> None:
    """The attestation sink can be chained; the audit log cannot, at any setting.

    The audit log is the record of what was decided. A deleted or edited line
    leaves no trace, and the machinery to fix that — fathom's
    ``ChainedAttestationLog`` — is already a dependency and already wired for
    attestation.
    """
    from fathom.chained_log import verify_chain

    audit_path = tmp_path / "chained-audit.jsonl"
    config = _config(tmp_path, audit={"path": str(audit_path), "chained": True})
    with _client(config) as client:
        assert _ask(client).status_code == 200
        public_key = client.app.state.broker._attestation.public_key  # noqa: SLF001

    assert verify_chain(audit_path, public_key).ok, "a freshly written audit chain does not verify"

    lines = audit_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[-1])
    tampered["record"]["decision"] = "deny"
    lines[-1] = json.dumps(tampered)
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not verify_chain(audit_path, public_key).ok, (
        "rewriting the decision on a line of a chained audit log went undetected"
    )


def test_b3d_a_chained_audit_log_without_a_signing_key_is_refused(tmp_path: Path) -> None:
    """Control: chaining signs each line, so it cannot be silently unsigned."""
    from nautilus.core.broker import Broker

    config = _config(
        tmp_path,
        audit={"path": str(tmp_path / "a.jsonl"), "chained": True},
        attestation={"enabled": False},
    )
    with pytest.raises(ValueError, match="chained"):
        Broker.from_config(config)


# ===========================================================================
# B3e -- a caller-supplied scope_constraints typo is a 500
# ===========================================================================


def test_b3e_a_malformed_scope_constraint_is_a_client_error(tmp_path: Path) -> None:
    """``context["scope_constraints"]`` is caller input validated with no guard.

    ``_merge_context_scope_constraints`` calls ``ScopeConstraint.model_validate``
    on whatever the caller sent; a typo raises ``ValidationError`` out of
    ``arequest``, which the REST app turns into a 500 and the audit log never
    records.
    """
    with _client(_config(tmp_path), raise_server_exceptions=False) as client:
        response = _ask(client, scope_constraints=[{"field": "region", "operator": "="}])
        assert response.status_code == 400, (
            f"a malformed scope constraint returned {response.status_code}, not a "
            f"client error: {response.text[:200]}"
        )


def test_b3e_a_well_formed_scope_constraint_still_applies(tmp_path: Path) -> None:
    """Control: the additive channel must keep working."""
    with _client(_config(tmp_path)) as client:
        response = _ask(
            client,
            scope_constraints=[
                {"source_id": "src", "field": "region", "operator": "=", "value": "eu"}
            ],
        )
        assert response.status_code == 200, response.text


# ===========================================================================
# B3f -- /readyz never probes the audit sink
# ===========================================================================


def test_b3f_readyz_fails_when_the_audit_sink_cannot_be_written(tmp_path: Path) -> None:
    """Every request writes an audit entry before it answers.

    A sink that cannot be written 500s every request, and the probe that exists
    to take a pod out of rotation reports ``ok`` throughout — it only exercises
    the session store.
    """
    audit_path = tmp_path / "audit.jsonl"
    with _client(_config(tmp_path)) as client:
        assert client.get("/readyz").status_code == 200
        audit_path.touch()
        audit_path.chmod(stat.S_IRUSR)
        try:
            assert client.get("/readyz").status_code == 503, (
                "/readyz reported ready with an unwritable audit sink"
            )
        finally:
            audit_path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_b3f_readyz_still_passes_with_a_healthy_sink(tmp_path: Path) -> None:
    """Control: the new probe must not fail an ordinary deployment."""
    with _client(_config(tmp_path)) as client:
        assert _ask(client).status_code == 200
        assert client.get("/readyz").status_code == 200


# ===========================================================================
# B3g -- config errors print resolved secrets
# ===========================================================================


def _config_error(tmp_path: Path, name: str, config: dict[str, Any]) -> str:
    from nautilus.config.loader import ConfigError, load_config

    path = tmp_path / f"{name}.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    try:
        load_config(str(path))
    except ConfigError as exc:
        return str(exc)
    pytest.fail(f"{name}: expected the config to be refused")


def test_b3g_a_config_error_does_not_print_the_secret_it_resolved(tmp_path: Path) -> None:
    """Interpolation resolves ``${VAR}`` and pydantic prints the input it rejected.

    So a config error puts an API key or a DSN password into stderr, and into
    whatever collects the container's startup logs — for a failure the operator
    is about to paste into a ticket.
    """
    bad_auth = _config_error(
        tmp_path,
        "bad-auth",
        {"sources": [{**_SOURCE, "auth": {"type": "weird", "password": "hunter2"}}]},
    )
    assert "hunter2" not in bad_auth, f"the source password is in the error text: {bad_auth}"

    bad_key = _config_error(
        tmp_path,
        "bad-key",
        {"sources": [_SOURCE], "api": {"keys": [{"key": "sup3rsecret", "capabilities": ["nope"]}]}},
    )
    assert "sup3rsecret" not in bad_key, f"the API key is in the error text: {bad_key}"


def test_b3g_a_config_error_still_names_what_is_wrong(tmp_path: Path) -> None:
    """Control: redaction must not cost the operator the diagnosis."""
    message = _config_error(
        tmp_path,
        "still-useful",
        {"sources": [{**_SOURCE, "auth": {"type": "weird", "password": "hunter2"}}]},
    )
    assert "sources.0.auth" in message, message
    assert "weird" in message, message
