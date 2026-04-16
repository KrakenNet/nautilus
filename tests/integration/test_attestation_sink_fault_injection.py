"""Attestation-sink fault-injection harness (Task 3.17, NFR-16, design §7.6).

Drives 1 000 ``broker.arequest`` calls through a :class:`Broker` whose
:class:`HttpAttestationSink` is wired to an :class:`httpx.MockTransport`
that alternates between success and raise. The harness locks in the
audit-first invariant (AC-14.5 / NFR-16):

* (a) Every request returns a :class:`BrokerResponse` — zero broker
  failures leaked out of the hot path, even when the sink raises on
  roughly half the emits.
* (b) Exactly 1 000 audit JSONL lines are written — one per request,
  regardless of attestation-sink outcome (NFR-8 / AC-7.1).
* (c) A ``WARNING`` log fires for every failed emit. ``HttpAttestationSink``
  absorbs transport errors internally and logs once at WARN after retries
  are exhausted — with ``max_retries=0`` that is one WARN per failure.

The test runs against the session-scoped ``pg_container`` fixture +
``tests/fixtures/nautilus.yaml`` so the broker hot path traverses the
real intent analyser, Fathom router, Postgres + pgvector adapters, and
audit writer — the sink failure is the only injected fault.
"""

from __future__ import annotations

import itertools
import json
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest

from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.core.attestation_sink import HttpAttestationSink, RetryPolicy
from nautilus.core.broker import Broker
from nautilus.core.models import AuditEntry, BrokerResponse

_TOTAL_REQUESTS: int = 1_000
_VERIFIER_URL: str = "https://verifier.test.local/attest"


def _install_alternating_transport(
    sink: HttpAttestationSink,
    counter: dict[str, int],
) -> None:
    """Swap the sink's internal ``httpx.AsyncClient`` for a fault-injecting one.

    The :class:`httpx.MockTransport` handler is called once per POST and
    alternates between a 200 response and a raised
    :class:`httpx.ConnectError`; the alternating decision is captured in
    ``counter`` so the test can assert the failure count post hoc.
    """
    toggle = itertools.cycle([True, False])  # True = success, False = raise

    def _handler(request: httpx.Request) -> httpx.Response:
        ok = next(toggle)
        if ok:
            counter["ok"] += 1
            return httpx.Response(200, json={"status": "accepted"})
        counter["fail"] += 1
        raise httpx.ConnectError("injected sink failure", request=request)

    # Replace the sink's pre-built AsyncClient with one pointed at the mock.
    # ``HttpAttestationSink`` defers network I/O to first use so hot-swapping
    # the client before the first emit is safe.
    sink._client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.integration
async def test_attestation_sink_fault_injection_1000_requests(
    pg_container: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """1000 requests with alternating-fail sink — broker stays up, audit intact.

    Asserts the three NFR-16 / AC-14.5 invariants:

    * Every ``broker.arequest`` returns a :class:`BrokerResponse`.
    * The audit JSONL carries exactly ``_TOTAL_REQUESTS`` lines.
    * The sink's WARN log count matches the injected-failure count.
    """
    del pg_container  # side-effect only — env vars exported
    monkeypatch.chdir(tmp_path)

    config_path = (Path(__file__).parent.parent / "fixtures" / "nautilus.yaml").resolve()
    broker = Broker.from_config(config_path)

    # Replace the default (null) sink with an HTTP sink whose transport
    # alternates success/raise. ``max_retries=0`` pins one attempt per emit
    # so the WARN-per-failed-emit count is exactly the failure count.
    sink = HttpAttestationSink(
        url=_VERIFIER_URL,
        retry_policy=RetryPolicy(max_retries=0, initial_backoff_s=0.0, max_backoff_s=0.0),
        dead_letter_path=None,
    )
    counter: dict[str, int] = {"ok": 0, "fail": 0}
    _install_alternating_transport(sink, counter)
    # Private attribute swap — the broker already constructed its default
    # NullAttestationSink; replace it before any request fires.
    broker._attestation_sink = sink  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    ctx: dict[str, Any] = {
        "clearance": "unclassified",
        "purpose": "threat-analysis",
        "session_id": "fault-inject",
        "embedding": [0.1, 0.2, 0.3],
    }

    responses: list[BrokerResponse] = []
    await broker.setup()
    try:
        with caplog.at_level(logging.WARNING, logger="nautilus.core.attestation_sink"):
            for i in range(_TOTAL_REQUESTS):
                resp = await broker.arequest(
                    "agent-alpha",
                    f"Find vulnerabilities for CVE-2026-{i:04d}",
                    ctx,
                )
                responses.append(resp)
    finally:
        await broker.aclose()

    # ------------------------------------------------------------------
    # (a) Every request returned a BrokerResponse — no broker failures.
    # ------------------------------------------------------------------
    assert len(responses) == _TOTAL_REQUESTS
    for resp in responses:
        assert isinstance(resp, BrokerResponse)
        # The attestation token is still signed and returned per AC-14.4;
        # sink outage MUST NOT null it out.
        assert resp.attestation_token is not None

    # ------------------------------------------------------------------
    # (b) Audit file has exactly _TOTAL_REQUESTS lines, each a valid entry.
    # ------------------------------------------------------------------
    audit_path = tmp_path / "audit.jsonl"
    assert audit_path.exists(), f"audit file missing at {audit_path}"
    audit_lines = [ln for ln in audit_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(audit_lines) == _TOTAL_REQUESTS, (
        f"expected {_TOTAL_REQUESTS} audit lines, got {len(audit_lines)}"
    )
    # Spot-check a handful of lines round-trip through AuditEntry — the
    # full-parse-every-line path is pinned by MVP e2e; here we sample so
    # the harness stays under the integration-suite wall-clock budget.
    for raw in (audit_lines[0], audit_lines[_TOTAL_REQUESTS // 2], audit_lines[-1]):
        record: dict[str, Any] = json.loads(raw)
        entry_json = record["metadata"][NAUTILUS_METADATA_KEY]
        entry = AuditEntry.model_validate_json(entry_json)
        assert entry.request_id
        assert entry.agent_id == "agent-alpha"

    # ------------------------------------------------------------------
    # (c) WARN log per failed emit — exactly counter['fail'] records.
    # ------------------------------------------------------------------
    # Both attempt counts must roughly balance (alternating) and sum to the
    # total emit attempts. ``HttpAttestationSink`` with ``max_retries=0``
    # issues one POST per emit, so counter totals == _TOTAL_REQUESTS.
    assert counter["ok"] + counter["fail"] == _TOTAL_REQUESTS
    assert counter["fail"] > 0, "expected at least one injected failure"

    sink_warns = [
        r
        for r in caplog.records
        if r.levelname == "WARNING" and "attestation_sink.http emit failed" in r.getMessage()
    ]
    assert len(sink_warns) == counter["fail"], (
        f"expected one WARN per injected failure (fail={counter['fail']}); got {len(sink_warns)}"
    )
