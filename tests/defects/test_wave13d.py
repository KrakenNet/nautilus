# pyright: reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false
"""WAVE 13d — what the credential-rotation wave (``e848b04``) left open.

Three defects, all downstream of the same commit.

**A caller can spell another caller's identity inside its own ``agent_id``.**
:func:`nautilus.core.principal.derive_principal_id` builds the exposure
ledger's key by joining ``agent``/``auth``/``peer`` components with U+001F and
hashing the result. Nothing rejected that byte inside a component, so an
``agent_id`` of ``"analyst\\x1fauth\\x1fkey\\x1fsvc"`` hashes to exactly what
``agent_id="analyst"`` under the authenticated principal ``key\\x1fsvc``
hashes to. Before ``e848b04`` the forgeable tail was ``\\x1f<the victim's API
key value>``, so forging it meant already holding the credential; the commit
made ``auth`` a *name* the operator writes in ``nautilus.yaml``, and the
precondition dropped from knowing a secret to knowing a name. Reachable
wherever the transport supplies neither ``auth`` nor ``peer``: MCP over stdio
(``_caller`` returns ``None`` and takes ``agent_id`` verbatim) and in-library
``Broker.arequest``.

**A post-reload listener could take the reload down with it.** ``on_reload``
is the extension point ``e848b04`` added so a transport re-reads the adopted
credential list. The loop that calls the listeners was unguarded and sat
between the generation swap and ``_retire``: a raise escaped ``reload()``,
``reload_config`` caught only ``ConfigNotReloadableError``, and the exception
was never retrieved -- no ``config_reload_refused`` entry, the outgoing
generation never retired, and any listener after the first never ran.

**The receipt did not mention the security budget the reload cleared.**
``_warn_about_orphaned_ledgers`` logs a warning and nothing else, so the audit
log recorded ``adopted api.keys`` while N cumulative-exposure ledgers were left
with nothing to accumulate under. The receipt is the artifact this product
exists to produce.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.defects.test_wave_ops13_credential_rotation import (
    _PURPOSE,
    _body,
    _document,
    _principal_rows,
    _serving,
    _write,
)

pytestmark = [pytest.mark.integration]

_SEP = "\x1f"
_VICTIM_KEY = "w13d-key-v1"
_ROTATED_KEY = "w13d-key-v2"
_VICTIM_PRINCIPAL = "svc"

# The whole of the victim's authenticated identity, spelled out inside a field
# the attacker fills in itself. Nothing here is a secret: ``key`` is the
# namespace ``ledger_identity`` stamps on a configured name, and ``svc`` is an
# ``api.keys[].principal`` -- an operator-chosen label that appears in
# ``nautilus.yaml``, in the orphaned-ledger warning and in the rotation runbook.
_FORGED_AGENT_ID = f"analyst{_SEP}auth{_SEP}key{_SEP}{_VICTIM_PRINCIPAL}"


def _victim_key_entry() -> dict[str, Any]:
    return {
        "key": _VICTIM_KEY,
        "principal": _VICTIM_PRINCIPAL,
        "capabilities": ["query"],
    }


def _write_with_purpose_window(path: Path, keys: list[Any]) -> Path:
    """The ops13 fixture with the purpose window on.

    ``session_store.purpose_ttl_seconds`` defaults to 0, which leaves
    ``purpose`` and ``purpose_start_ts`` off the ledger row entirely -- and
    those are the fields a forger can still move in a deployment whose
    ``agents:`` registry refuses the request it made to move them.
    """
    document = _document(path, keys)
    document["session_store"] = {"purpose_ttl_seconds": 3600}
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _audit_lines(config_path: Path) -> list[dict[str, Any]]:
    """Every ``AuditEntry`` on the sink.

    The sink writes a decision record and carries the entry inside it as JSON
    under ``metadata.nautilus_audit_entry``, so reading the outer object alone
    finds no ``event_type`` on anything.
    """
    audit = config_path.parent / "audit.jsonl"
    if not audit.exists():
        return []
    return [
        json.loads(json.loads(line)["metadata"]["nautilus_audit_entry"])
        for line in audit.read_text(encoding="utf-8").splitlines()
        if line
    ]


# ---------------------------------------------------------------------------
# 1. The exposure ledger's key is not forgeable from a component.
# ---------------------------------------------------------------------------


def test_a_component_carrying_the_separator_is_refused_before_it_is_hashed() -> None:
    """The separator is structure, so a component may not contain one.

    ``derive_principal_id`` distinguishes its components by a byte alone. A
    component free to carry that byte is a component free to declare components
    that were never supplied, which is the whole of the forgery: the digest
    cannot tell "one agent id" from "an agent id, an auth marker and a
    principal".

    Refusal rather than escaping: escaping would change the digest for inputs
    that are valid today and orphan every ledger a running deployment holds.

    ``auth_principal`` is the one component with a legitimate separator in it
    -- ``ledger_identity`` namespaces a configured ``api.keys[].principal`` as
    ``key<SEP><name>`` -- so what is refused there is any *other* shape, and the
    namespaced one has to keep working or naming a principal stops working at
    all.
    """
    from nautilus.core.principal import derive_principal_id

    for kwargs in (
        {"agent_id": _FORGED_AGENT_ID},
        {"agent_id": "analyst", "auth_principal": f"key{_SEP}a{_SEP}peer{_SEP}b"},
        {"agent_id": "analyst", "auth_principal": f"notkey{_SEP}svc"},
        {"agent_id": "analyst", "auth_principal": f"key{_SEP}"},
        {"agent_id": "analyst", "peer": f"10.0.0.5{_SEP}auth{_SEP}key{_SEP}svc"},
    ):
        with pytest.raises(ValueError, match=r"U\+001F"):
            derive_principal_id(**kwargs)  # type: ignore[arg-type]

    derive_principal_id("analyst", auth_principal=f"key{_SEP}svc")  # the shape that is structure


def test_the_refusal_does_not_repeat_the_value_it_refused() -> None:
    """For a credential naming no principal, ``auth_principal`` *is* the secret.

    ``ledger_identity`` falls back to the raw key value for an entry with no
    ``principal``, so the message this refusal raises travels into an HTTP 400
    body and a process log with a live credential in it unless it names only
    the field.
    """
    from nautilus.core.principal import derive_principal_id

    secret = f"super-secret-key{_SEP}spliced"
    with pytest.raises(ValueError) as caught:
        derive_principal_id("analyst", auth_principal=secret)
    assert "super-secret-key" not in str(caught.value), (
        f"the refusal quoted the value it refused, which for an unnamed entry is "
        f"the API key itself: {caught.value}"
    )
    assert "auth_principal" in str(caught.value), (
        f"the refusal did not say which field was wrong: {caught.value}"
    )


def test_the_digest_is_unchanged_for_every_input_that_is_valid_today() -> None:
    """Pinned by value: a ledger written before this fix must still resolve.

    Rejecting rather than escaping is what makes this hold — these three
    digests are the ones ``e848b04`` shipped, and a running deployment's
    ``principal:`` rows are keyed by them.
    """
    from nautilus.core.principal import derive_principal_id

    assert derive_principal_id("analyst") == "principal:e263a66a7f86bfdb517083d1ab65a1da"
    assert (
        derive_principal_id("analyst", auth_principal=f"key{_SEP}svc")
        == "principal:06e003e37a717a08bfea69276d3c6c14"
    )
    assert (
        derive_principal_id("analyst", peer="10.0.0.5")
        == "principal:139baaa3ee8f2c8da3f6093ffaa13d7d"
    )


@pytest.mark.asyncio
async def test_an_unauthenticated_caller_cannot_write_into_an_authenticated_ledger(
    tmp_path: Path,
) -> None:
    """The consequence, end to end, on the two surfaces that reach it.

    The victim queries over REST holding a credential that names
    ``principal: svc``; its cumulative exposure accumulates under the digest of
    ``agent\\x1fanalyst\\x1fauth\\x1fkey\\x1fsvc``. The attacker then calls the
    broker the way MCP-over-stdio and an in-library caller do -- ``caller=None``,
    ``agent_id`` taken verbatim -- and spells those same components inside its
    own ``agent_id``.

    The row the attacker reaches is the whole ledger record, so the assertion
    is over the whole record. What it can write there depends on the config:
    every field this deployment's ``agents:`` registry does not stop it from
    writing (``last_request_id``, ``last_sources_queried``, and the
    ``purpose``/``purpose_start_ts`` window ``purpose-expired-deny`` reads --
    an attacker that restarts that window at will has disabled the rule for
    the victim), and, in a deployment that registers no agents at all,
    ``sources_visited`` / ``data_types_seen`` / ``pii_sources_accessed_list``
    themselves: the attacker's own exposure inflating a budget the victim is
    then denied against.
    """
    config_path = _write_with_purpose_window(tmp_path / "nautilus.yaml", [_victim_key_entry()])
    async for broker, client in _serving(config_path):
        assert (
            await client.post(
                "/v1/request", headers={"X-API-Key": _VICTIM_KEY}, json=_body("alpha", "victim-s")
            )
        ).status_code == 200
        before = {key: dict(row) for key, row in _principal_rows(broker).items()}
        assert len(before) == 1, f"fixture did not produce one victim ledger: {before}"
        victim_key, victim_row = next(iter(before.items()))
        assert victim_row.get("sources_visited") == ["alpha"] and victim_row.get(
            "purpose_start_ts"
        ), (
            f"control failed: the victim's REST request accumulated nothing, so this "
            f"pin cannot show anything landing on it: {victim_row}"
        )

        # The ledger is checked before the refusal is: what makes this a defect
        # is that an unauthenticated caller reached the row at all, not which
        # exception eventually said no.
        refused: ValueError | None = None
        try:
            await broker.arequest(
                _FORGED_AGENT_ID,
                "read the beta records",
                {"purpose": _PURPOSE["beta"], "session_id": "attacker-s"},
            )
        except ValueError as exc:
            refused = exc

        after = _principal_rows(broker)
        assert after.get(victim_key) == victim_row, (
            f"a caller that presented no credential wrote into the authenticated "
            f"caller's ledger {victim_key}: {victim_row} became {after.get(victim_key)}"
        )
        assert refused is not None and "U+001F" in str(refused), (
            f"the forged agent_id was not refused, it merely missed: {refused}"
        )


def test_a_principal_holding_a_control_character_is_refused_at_config_load() -> None:
    """Closed from the operator's end too, so it fails at load and not per request.

    ``ledger_identity`` hands a configured ``principal`` straight to
    ``derive_principal_id`` as ``auth_principal``. Left unconstrained, a name
    with a control character in it loads fine and then refuses every request
    the credential makes -- a config-time mistake reported as a runtime 400 on
    the hot path.
    """
    from pydantic import ValidationError

    from nautilus.config.models import ApiKeyEntry

    ApiKeyEntry(key="k", principal="reporting-service")  # the shape that must still load
    with pytest.raises(ValidationError):
        ApiKeyEntry(key="k", principal=f"reporting{_SEP}service")


# ---------------------------------------------------------------------------
# 2. A listener cannot take the reload down with it.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_failing_reload_listener_neither_escapes_nor_starves_the_others(
    tmp_path: Path,
) -> None:
    """``on_reload`` is a public extension point, so it is a caller of unknown code.

    The listeners run after the generation swap and before ``_retire``. An
    escaping raise meant the reload had already happened but was never
    recorded, the outgoing router and retired adapters were never closed, and
    every listener after the first was skipped -- so a second transport went on
    serving the retired credential while the audit log said nothing.
    """
    from nautilus.cli.serve import reload_config

    config_path = _write(tmp_path / "nautilus.yaml", [_VICTIM_KEY])
    ran: list[str] = []
    adopted = False

    async for broker, _client in _serving(config_path):

        def _explodes() -> None:
            ran.append("first")
            raise RuntimeError("this listener is someone else's code")

        def _records() -> None:
            ran.append("second")

        broker.on_reload(_explodes)
        broker.on_reload(_records)
        _write(config_path, [_ROTATED_KEY])
        adopted = await reload_config(broker, config_path, air_gapped=False)

    assert adopted, "a listener's failure refused a reload that had already been applied"
    assert ran == ["first", "second"], (
        f"a raise from one listener starved the ones after it: ran={ran}"
    )
    reloaded = [e for e in _audit_lines(config_path) if e.get("event_type") == "config_reloaded"]
    assert reloaded, "the reload happened and the audit log does not say so"


# ---------------------------------------------------------------------------
# 3. The receipt names the exposure budget the reload cleared.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_receipt_records_the_exposure_ledgers_the_reload_orphaned(
    tmp_path: Path,
) -> None:
    """A warning is for the operator watching; the receipt is for the one who was not.

    Rotating a key that names no ``principal`` clears that caller's cumulative
    exposure -- a security budget reset by a routine operation. The audit entry
    recorded ``adopted api.keys``, which says a credential changed and not that
    anything was cleared, and the audit log is the artifact that has to answer
    for the decision afterwards.
    """
    from nautilus.cli.serve import reload_config

    config_path = _write(tmp_path / "nautilus.yaml", [_VICTIM_KEY])
    async for broker, client in _serving(config_path):
        assert (
            await client.post(
                "/v1/request", headers={"X-API-Key": _VICTIM_KEY}, json=_body("alpha", "s")
            )
        ).status_code == 200
        _write(config_path, [_ROTATED_KEY])
        assert await reload_config(broker, config_path, air_gapped=False)

    reloaded = [e for e in _audit_lines(config_path) if e.get("event_type") == "config_reloaded"]
    assert len(reloaded) == 1, f"expected one config_reloaded entry, got {len(reloaded)}"
    detail = reloaded[0]["raw_intent"]
    assert "api.keys" in detail, f"the receipt lost what it adopted: {detail!r}"
    assert "1" in detail and "ledger" in detail, (
        f"the receipt says a credential changed but not that a cumulative-exposure "
        f"ledger was cleared with it: {detail!r}"
    )
    assert _VICTIM_KEY not in detail and _ROTATED_KEY not in detail, (
        "the receipt printed a credential; the audit log is not a place for secrets"
    )
