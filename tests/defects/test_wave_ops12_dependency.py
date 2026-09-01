"""WAVE ops12 — a dead dependency had no name, and the SSRF guard had no teeth.

A sealed operator trial, configured from ``docs/`` alone and measured against a
live broker, failed the goal state *"when a dependency goes away, the process
names it"* and found the SSRF control documented in
``docs/reference/errors/adapters.md`` to be weaker than its own page.

**The dependency had no name.** With a ``type: rest`` source's backend stopped,
``POST /v1/request`` answered ``200`` with ``sources_errored:
[{"source_id": "catalog", "error_type": "AdapterError", "message":
"RestAdapter: execute failed for source 'catalog': ReadTimeout: "}]``; stdout at
``--log-level debug`` carried no record from any ``nautilus.*`` logger; and
``grep -c <backend-host> audit.jsonl`` returned ``0``. A ``source_id`` is the
operator's *label* for a dependency, not its address, and the address was in
nothing the broker wrote. The operator-guide sentence for exactly this
situation — requests are denied *"with the connect error"* — reads as a promise
that the error identifies the connection, and it did not.

**The guard had no teeth.** The error reference says a ``base_url``
*"resolving to"* a private, loopback or link-local address is refused. The
check ran on an IP *literal* only, so ``http://nautaudit-sut-backend`` —
resolving to ``172.27.0.6`` from inside the broker — was accepted and dialled,
and every internal service with a DNS name, including a cloud metadata service
fronted by a name, went straight through a control the documentation said
covered it.

What these pin:

* every per-source failure carries ``ErrorRecord.endpoint``, into the response
  *and* the durable audit entry, and leaves one ``WARNING`` on the broker's own
  logger;
* that endpoint is built from scheme/host/port only, so a DSN password cannot
  ride out of ``nautilus.yaml`` into a log, an audit record or an agent's
  response;
* the SSRF guards resolve names, refuse what resolves unroutably, and are one
  function rather than a copy per adapter;
* neither of the two messages an operator gets for a failed source ends in a
  colon with nothing after it.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest
import yaml

from nautilus.adapters import llm as llm_module
from nautilus.adapters import rest as rest_module
from nautilus.adapters import servicenow as servicenow_module
from nautilus.adapters.base import ScopeEnforcementError, resolve_base_url
from nautilus.adapters.rest import SSRFBlockedError
from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.config.models import redact_connection
from nautilus.core.broker import Broker

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = [pytest.mark.integration]

# A password in the config, so "the endpoint must not carry a credential" is
# asserted against a real one rather than against an empty string.
_DSN_PASSWORD = "ops12-dsn-password"  # noqa: S105 — fixture value, not a credential
_LEDGER_DSN = f"postgresql://nautilus:{_DSN_PASSWORD}@ledger.example.invalid:5432/app"
# ``.invalid`` is reserved by RFC 2606 and resolves nowhere, so the dial fails
# the same way on a laptop and in an air-gapped CI.
_CATALOG_URL = "http://catalog.example.invalid"


def _config(path: Path) -> str:
    document: dict[str, Any] = {
        "sources": [
            {
                "id": "catalog",
                "type": "rest",
                "classification": "unclassified",
                "data_types": ["catalog"],
                "connection": _CATALOG_URL,
                "endpoints": [{"path": "/catalog.json", "method": "GET"}],
                "timeout_s": 5.0,
            },
            {
                "id": "ledger",
                "type": "postgres",
                "classification": "unclassified",
                "data_types": ["ledger"],
                "connection": _LEDGER_DSN,
                "table": "entries",
                "timeout_s": 5.0,
            },
        ],
        "agents": {"a1": {"id": "a1", "clearance": "unclassified"}},
        "audit": {"path": str(path.parent / "audit.jsonl")},
        "analysis": {"keyword_map": {"catalog": ["catalog"], "ledger": ["ledger"]}},
    }
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


async def _ask(tmp_path: Path, intent: str) -> tuple[Any, list[dict[str, Any]]]:
    """Run one request and return the response plus the audit entries written."""
    broker = await Broker.afrom_config(_config(tmp_path / "nautilus.yaml"))
    try:
        response = await broker.arequest("a1", intent)
    finally:
        await broker.aclose()
    # The full ``AuditEntry`` rides inside the Fathom record's metadata; the
    # sink writes it as a JSON string under one key.
    entries = [
        json.loads(json.loads(line)["metadata"][NAUTILUS_METADATA_KEY])
        for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return response, entries


# ---------------------------------------------------------------------------
# 1. The dependency is named — in the response, the log, and the audit trail.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_failed_source_names_the_backend_it_could_not_reach(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The error record and one log line both carry the address that failed.

    Before: the request answered ``200`` with an error bucket that named the
    source id and the driver's exception class, and there was no way to learn
    *what* was unreachable without already knowing.
    """
    with caplog.at_level(logging.WARNING, logger="nautilus.core.broker"):
        response, entries = await _ask(tmp_path, "show me the catalog")

    errored = {e.source_id: e for e in response.sources_errored}
    assert "catalog" in errored, f"expected the rest source to fail, got {response!r}"
    assert errored["catalog"].endpoint == _CATALOG_URL

    # The durable trail carries it too: the trial's `grep -c <host> audit.jsonl`
    # returned 0.
    records = [r for entry in entries for r in entry.get("error_records", [])]
    assert any(r["source_id"] == "catalog" and r["endpoint"] == _CATALOG_URL for r in records), (
        f"the audit entry does not name the backend: {records!r}"
    )

    # And the process says something on its own logger, at WARNING, not only at
    # debug and not only from httpcore.
    warnings = [r.getMessage() for r in caplog.records if r.name == "nautilus.core.broker"]
    assert any("catalog.example.invalid" in m for m in warnings), (
        f"no nautilus.* log record named the dead dependency: {warnings!r}"
    )


@pytest.mark.asyncio
async def test_the_named_endpoint_never_carries_the_dsn_password(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Naming the backend must not widen who can read the credential.

    ``connection`` can be a DSN with a password or a URL with a token. The
    response, the process log and the audit file are each read by a wider
    audience than ``nautilus.yaml``, so the endpoint is rebuilt from
    scheme/host/port and nothing else.
    """
    with caplog.at_level(logging.DEBUG):
        response, entries = await _ask(tmp_path, "show me the ledger")

    errored = {e.source_id: e for e in response.sources_errored}
    assert "ledger" in errored, f"expected the postgres source to fail, got {response!r}"
    assert errored["ledger"].endpoint == "postgresql://ledger.example.invalid:5432"

    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    logged = "\n".join(r.getMessage() for r in caplog.records)
    for surface, text in (
        ("the response", response.model_dump_json()),
        ("the audit file", audit_text),
        ("the process log", logged),
    ):
        assert _DSN_PASSWORD not in text, f"the DSN password reached {surface}"
    # ...while the part an operator needs is present in all three.
    assert "ledger.example.invalid" in audit_text
    assert "ledger.example.invalid" in logged
    assert entries, "no audit entry was written"


def test_redact_connection_copies_out_scheme_host_port_and_nothing_else() -> None:
    """The redactor is an allowlist, so no unanticipated credential slot leaks.

    Stripping ``user:pw@`` would still have carried ``?password=`` and a token
    in the path; only scheme, host and port are copied forward.
    """
    assert (
        redact_connection("https://u:pw@api.example.com/hooks/T0/B0/SECRET?token=abc#f")
        == "https://api.example.com"
    )
    assert (
        redact_connection("postgresql://u:pw@db:5432/app?password=other") == "postgresql://db:5432"
    )
    assert redact_connection("http://[2001:db8::1]:9200/idx") == "http://[2001:db8::1]:9200"
    # Nothing host-shaped: a guess is how the withheld half gets echoed by
    # accident, so there is no guess.
    for opaque in ("", "/var/lib/rows.json", "host=db password=pw", "memory://"):
        assert redact_connection(opaque) is None


# ---------------------------------------------------------------------------
# 2. The SSRF guard runs on what the host resolves to, in one place.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_name_that_resolves_to_loopback_is_refused() -> None:
    """``localhost`` is a *name*, not an IP literal — and it was accepted.

    This is the whole shape of the bypass: the trial pointed a source at
    ``http://nautaudit-sut-backend``, which resolved to an RFC1918 address, and
    the adapter dialled it. ``localhost`` reproduces it without needing a
    resolver that answers anything in particular.
    """
    with pytest.raises(SSRFBlockedError, match="resolves to"):
        await rest_module._reject_unroutable_base_url("http://localhost:9")  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_name_that_resolves_to_rfc1918_is_refused() -> None:
    """The container-service-name case, with the resolver's answer pinned."""
    with (
        mock.patch.object(
            rest_module,
            "resolve_base_url",
            return_value=("backend", [ipaddress.ip_address("172.27.0.6")]),
        ),
        pytest.raises(SSRFBlockedError, match="172.27.0.6"),
    ):
        await rest_module._reject_unroutable_base_url("http://backend")  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_routable_host_is_still_accepted() -> None:
    """The control refuses unroutable answers, not every name."""
    with mock.patch.object(
        rest_module,
        "resolve_base_url",
        return_value=("api.example.com", [ipaddress.ip_address("93.184.216.34")]),
    ):
        await rest_module._reject_unroutable_base_url("https://api.example.com")  # noqa: SLF001


@pytest.mark.asyncio
async def test_an_unresolvable_host_is_accepted_and_fails_at_the_dial() -> None:
    """A host with no address reaches nothing; refusing it would buy nothing.

    Stated so the residual is a decision rather than an accident: this is why
    ``_CATALOG_URL`` above gets past the guard and fails at ``execute``.
    """
    host, addresses = await resolve_base_url(_CATALOG_URL, "RestAdapter")
    assert host == "catalog.example.invalid"
    assert addresses == []
    await rest_module._reject_unroutable_base_url(_CATALOG_URL)  # noqa: SLF001


@pytest.mark.asyncio
async def test_an_ip_literal_is_still_refused_without_a_lookup() -> None:
    """Resolution is additive: the literal case did work and must keep working."""
    with pytest.raises(SSRFBlockedError, match="169.254.169.254"):
        await rest_module._reject_unroutable_base_url("http://169.254.169.254/latest/meta-data")  # noqa: SLF001


def test_the_guard_is_one_function_that_every_dialling_adapter_shares() -> None:
    """A guard belongs where all callers route through, not once per adapter.

    ``ServiceNowAdapter`` sends the session-provenance token on every request
    and must not be able to drift from ``RestAdapter``'s policy; both LLM and
    REST resolve through the same seam, so a fix lands once.
    """
    assert (
        servicenow_module._reject_unroutable_base_url  # noqa: SLF001
        is rest_module._reject_unroutable_base_url  # noqa: SLF001
    )
    assert rest_module.resolve_base_url is resolve_base_url
    assert llm_module.resolve_base_url is resolve_base_url


@pytest.mark.asyncio
async def test_the_llm_metadata_block_also_survives_a_dns_name() -> None:
    """Every cloud metadata service answers to a name as well as to 169.254.x.x."""
    with (
        mock.patch.object(
            llm_module,
            "resolve_base_url",
            return_value=("metadata.google.internal", [ipaddress.ip_address("169.254.169.254")]),
        ),
        pytest.raises(ScopeEnforcementError, match="link-local"),
    ):
        await llm_module._reject_unroutable_base_url(  # noqa: SLF001
            "http://metadata.google.internal/v1"
        )


@pytest.mark.asyncio
async def test_a_refused_base_url_does_not_echo_the_connection_string() -> None:
    """A malformed connection is the shape that still carries ``user:pw@``."""
    with pytest.raises(ScopeEnforcementError) as caught:
        await resolve_base_url("http://someone:hunter2@", "RestAdapter")
    assert "hunter2" not in str(caught.value)


# ---------------------------------------------------------------------------
# 3. Neither message trails off into a colon.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_neither_source_failure_message_ends_in_a_dangling_colon(
    tmp_path: Path,
) -> None:
    """``ReadTimeout: `` and ``timeout_s budget: `` were the entire operator text.

    Both rendered an exception whose ``str()`` is empty straight into the
    template.
    """
    response, _ = await _ask(tmp_path, "show me the catalog and the ledger")
    assert response.sources_errored, "expected both sources to fail"
    for record in response.sources_errored:
        assert not record.message.rstrip().endswith(":"), (
            f"{record.source_id} still trails off: {record.message!r}"
        )


@pytest.mark.asyncio
async def test_a_timed_out_source_names_the_budget_it_spent(tmp_path: Path) -> None:
    """``exceeded the source's timeout_s budget: `` said nothing about the budget."""
    broker = await Broker.afrom_config(_config(tmp_path / "nautilus.yaml"))
    try:
        assert broker._timeout_message("catalog") == (  # noqa: SLF001
            "exceeded the source's timeout_s budget of 5.0s"
        )
    finally:
        await broker.aclose()
