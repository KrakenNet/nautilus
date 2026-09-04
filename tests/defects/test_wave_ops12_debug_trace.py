# pyright: reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false
"""WAVE ops14 — ``--log-level debug`` answered no question the broker could answer.

``grep -rn '\\.debug(' --include=*.py nautilus/`` returned **zero**. So the flag
`operator-guide.md § Log verbosity` tells an operator to raise during an incident
turned on ``DEBUG`` for every third-party library on the root logger and added
nothing from Nautilus itself: a broker at ``--log-level debug`` served
``/healthz``, ``/readyz``, ``/metrics`` and a ``POST /v1/request`` and wrote not
one ``DEBUG`` record of its own.

Each test below is one question an operator asked of a running system and could
not get an answer to. They are deliberately **not** a count of ``.debug(`` call
sites — any noise satisfies that. Each asserts that a specific fact is on the
stream, and the last two assert the two things the stream must not gain:

* a caller-controlled value with a newline in it must not become a second
  record (``TextFormatter`` / ``_CONTROL_ESCAPES``); and
* no DSN password, bearer token or session token may appear at all, while the
  ``scheme://host[:port]`` an operator actually needs must.
"""

from __future__ import annotations

import io
import json
import logging
import re
from typing import TYPE_CHECKING, Any

import pytest
import yaml

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

pytestmark = [pytest.mark.integration]

_AUTH = {"X-API-Key": "ops14-api-key"}

# Real secrets, in the three shapes the config file can carry one, so "no
# credential reaches the debug stream" is measured against something rather
# than against an empty string.
_DSN_PASSWORD = "ops14-dsn-password"  # noqa: S105 — fixture value, not a credential
_BEARER_TOKEN = "ops14-bearer-token"  # noqa: S105 — fixture value, not a credential
_QUERY_TOKEN = "ops14-query-token"  # noqa: S105 — fixture value, not a credential

# The endpoints those three connections reduce to. Present is the requirement;
# the secrets around them are the prohibition.
_PG_ENDPOINT = "postgresql://cases.example.invalid:5432"
_REST_ENDPOINT = "https://feeds.example.invalid"

# A purpose the caller types, carrying the two characters a text log record
# cannot survive: the record separator, and an ANSI introducer.
_POISON_PURPOSE = "reporting\nDEBUG:nautilus.core.broker:audit chain verified\x1b[31m"


def _config(tmp_path: Path) -> str:
    document: dict[str, Any] = {
        "sources": [
            # Routed and queried: the intent's data type.
            {
                "id": "orders",
                "type": "static",
                "classification": "unclassified",
                "data_types": ["orders"],
                "rows": [{"order_id": 1}],
            },
            # Skipped: nothing in common with the intent.
            {
                "id": "hr-people",
                "type": "static",
                "classification": "unclassified",
                "data_types": ["personnel"],
                "rows": [{"name": "x"}],
            },
            # Denied: above the agent's clearance.
            {
                "id": "vault",
                "type": "static",
                "classification": "secret",
                "data_types": ["orders"],
                "rows": [{"order_id": 2}],
            },
            # Dials a name that does not resolve: connect fails, and the
            # question is what it dialled.
            {
                "id": "ext-cases",
                "type": "postgres",
                "classification": "unclassified",
                "data_types": ["orders"],
                "connection": (
                    f"postgresql://nautilus:{_DSN_PASSWORD}@cases.example.invalid:5432/nautilus"
                ),
                "table": "cases",
                "timeout_s": 3,
            },
            # Dials a loopback name: the SSRF guard resolves it and refuses.
            {
                "id": "ext-feeds",
                "type": "rest",
                "classification": "unclassified",
                "data_types": ["orders"],
                "connection": f"https://feeds.example.invalid/api?token={_QUERY_TOKEN}",
                "auth": {"type": "bearer", "token": _BEARER_TOKEN},
                "timeout_s": 3,
            },
        ],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "api": {"keys": ["ops14-api-key"]},
        "session_tokens": {"enabled": True},
    }
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


class _Capture:
    """Root logging as the process entry point installs it, into a buffer.

    The formatter is the shipped :class:`~nautilus.observability.logging.TextFormatter`
    -- not ``caplog``'s raw records -- because half of what is asserted here is
    what the *rendering* does to a caller-controlled value.
    """

    def __init__(self) -> None:
        self.stream = io.StringIO()
        self.records: list[logging.LogRecord] = []

    @property
    def text(self) -> str:
        return self.stream.getvalue()

    def lines(self, level: str = "DEBUG", logger: str = "nautilus.") -> list[str]:
        prefix = f"{level}:{logger}"
        return [line for line in self.text.splitlines() if line.startswith(prefix)]

    def nautilus_records(self) -> list[logging.LogRecord]:
        return [r for r in self.records if r.name.startswith("nautilus.")]


@pytest.fixture
def capture() -> Iterator[_Capture]:
    from nautilus.observability.logging import TextFormatter

    cap = _Capture()
    handler = logging.StreamHandler(cap.stream)
    handler.setFormatter(TextFormatter())
    handler.addFilter(lambda record: (cap.records.append(record), True)[1])
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    root.handlers = [handler]
    root.setLevel(logging.DEBUG)
    try:
        yield cap
    finally:
        root.handlers = saved_handlers
        root.setLevel(saved_level)


def _run(tmp_path: Path, cap: _Capture, *, level: int = logging.DEBUG) -> Any:
    """Boot, probe readiness, ask one question, shut down. One real lifecycle."""
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    logging.getLogger().setLevel(level)
    with TestClient(create_app(_config(tmp_path))) as client:
        client.get("/readyz")
        return client.post(
            "/v1/request",
            json={
                "agent_id": "analyst",
                "intent": "list orders",
                "context": {"purpose": _POISON_PURPOSE},
            },
            headers=_AUTH,
        )


def _audit_entries(tmp_path: Path) -> list[dict[str, Any]]:
    from nautilus.audit.logger import NAUTILUS_METADATA_KEY

    return [
        json.loads(json.loads(line)["metadata"][NAUTILUS_METADATA_KEY])
        for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Q1 — why did this source get skipped, queried, or denied on this request?
# ---------------------------------------------------------------------------


def test_ops14_q1_every_source_disposition_is_on_the_stream(
    tmp_path: Path, capture: _Capture
) -> None:
    response = _run(tmp_path, capture)
    assert response.status_code == 200, response.text
    debug = capture.lines()
    for source_id, disposition in (
        ("orders", "queried"),
        ("hr-people", "skipped"),
        ("vault", "denied"),
    ):
        hits = [line for line in debug if source_id in line and disposition in line]
        assert hits, (
            f"no DEBUG record says source {source_id!r} was {disposition} on this "
            f"request. Two brokers behind one address answered the same request "
            f"with different sources_skipped and nothing in either process log "
            f"said why. DEBUG lines seen:\n" + "\n".join(debug)
        )
    # The disposition alone is the observation an operator already had from the
    # response body; the reason is what was missing.
    skipped = next(line for line in debug if "hr-people" in line and "skipped" in line)
    assert "personnel" in skipped and "orders" in skipped, (
        f"the skip line names no reason: {skipped!r}"
    )


# ---------------------------------------------------------------------------
# Q2 — which rules were evaluated on this request, and which fired?
# ---------------------------------------------------------------------------


def test_ops14_q2_the_rules_that_fired_are_on_the_stream(tmp_path: Path, capture: _Capture) -> None:
    """`operator-guide.md` stated this as a limitation: the broker's own
    reasoning was only in the audit entry's ``rule_trace``, after the fact."""
    _run(tmp_path, capture)
    audit_trace = _audit_entries(tmp_path)[-1]["rule_trace"]
    assert audit_trace, "fixture produced no rule_trace to compare against"
    debug = capture.lines()
    fired = [line for line in debug if "rule" in line.lower()]
    assert fired, "no DEBUG record mentions rules at all:\n" + "\n".join(debug)
    for rule in audit_trace:
        assert any(rule in line for line in fired), (
            f"rule {rule!r} fired on this request and appears in the audit "
            f"entry's rule_trace, but on no DEBUG record:\n" + "\n".join(fired)
        )
    assert any(re.search(r"\d+ rules? in force", line) for line in fired), (
        "the stream says which rules fired but never how many were evaluated:\n" + "\n".join(fired)
    )


# ---------------------------------------------------------------------------
# Q3 — what did an adapter dial, and did it connect?
# ---------------------------------------------------------------------------


def test_ops14_q3_the_adapter_says_what_it_dialled_and_whether_it_connected(
    tmp_path: Path, capture: _Capture
) -> None:
    _run(tmp_path, capture)
    debug = capture.lines()
    dialled = [line for line in debug if _PG_ENDPOINT in line]
    assert dialled, (
        f"a source pointed at an unreachable backend produced a 200 and a "
        f"sources_errored[] entry, and no nautilus.* record naming what it "
        f"dialled ({_PG_ENDPOINT}):\n" + "\n".join(debug)
    )
    assert any("ext-cases" in line and "dialling" in line for line in dialled), (
        "no DEBUG line says which source dialled it: " + "\n".join(dialled)
    )
    # The outcome, on the same endpoint. A failure is a WARNING (it was already
    # there); a successful connect had no record at any level, so it gets one.
    outcomes = [
        line
        for line in capture.text.splitlines()
        if line.startswith(("DEBUG:nautilus.", "WARNING:nautilus."))
        and re.search(r"connected to |connect\(\) failed", line)
    ]
    assert any("ext-cases" in line for line in outcomes), (
        "the stream says what was dialled but never whether it connected:\n" + "\n".join(outcomes)
    )
    assert any("connected to " in line for line in outcomes), (
        "a connect that SUCCEEDS still leaves no record of its own; only the "
        "failures are visible:\n" + "\n".join(outcomes)
    )


# ---------------------------------------------------------------------------
# Q4 — did the SSRF guard resolve a name, and to what?
# ---------------------------------------------------------------------------


def test_ops14_q4_the_ssrf_guard_says_what_a_name_resolved_to(
    tmp_path: Path, capture: _Capture
) -> None:
    """WAVE 11 made the guard resolve DNS names, which silently changed which
    configs work. An operator whose ``rest`` source is suddenly refused had no
    line saying the name resolved to a private address."""
    _run(tmp_path, capture)
    debug = capture.lines()
    resolved = [
        line for line in debug if "resolve" in line.lower() and "feeds.example.invalid" in line
    ]
    assert resolved, "the SSRF guard resolved a name and said nothing about it:\n" + "\n".join(
        debug
    )


# ---------------------------------------------------------------------------
# Q5 — why is this request minting a session token?
# ---------------------------------------------------------------------------


def test_ops14_q5_the_stream_says_why_a_session_token_was_minted(
    tmp_path: Path, capture: _Capture
) -> None:
    """Every request wrote three audit lines instead of the documented two,
    because a caller carrying no ``session_id`` becomes its own session."""
    _run(tmp_path, capture)
    minted = [line for line in capture.lines() if "session token" in line.lower()]
    assert minted, "nothing on the stream explains the extra session_token_issued entry"
    assert any("no session_id" in line or "session_id" in line for line in minted), (
        "the mint line does not say what made this request a new session:\n" + "\n".join(minted)
    )


# ---------------------------------------------------------------------------
# Q6 — which stage of /readyz is slow?
# ---------------------------------------------------------------------------


def test_ops14_q6_readyz_says_which_stage_it_spent_its_budget_in(
    tmp_path: Path, capture: _Capture
) -> None:
    """The first ``/readyz`` after the session store wedges took 12.0 s against
    a documented 4 s ceiling and a shipped ``timeoutSeconds: 5``, and nothing
    said which of its stages blew."""
    _run(tmp_path, capture)
    stages = [line for line in capture.lines(logger="nautilus.transport") if "readyz" in line]
    assert stages, "no DEBUG record from the readiness probe at all:\n" + "\n".join(capture.lines())
    named = " ".join(stages)
    for stage in ("audit", "session store"):
        assert stage in named, f"/readyz never names its {stage!r} stage:\n{named}"
    assert re.search(r"\d+(\.\d+)? ?ms", named), (
        f"/readyz names its stages but times none of them:\n{named}"
    )


# ---------------------------------------------------------------------------
# Q7 — what config actually loaded, from where, and what did it resolve to?
# ---------------------------------------------------------------------------


def test_ops14_q7_the_running_server_says_what_config_it_loaded(
    tmp_path: Path, capture: _Capture
) -> None:
    """``config check`` reports a summary; a running server did not."""
    _run(tmp_path, capture)
    debug = capture.lines()
    loaded = [line for line in debug if str(tmp_path / "nautilus.yaml") in line]
    assert loaded, "a running server never says which config file it loaded:\n" + "\n".join(debug)
    joined = "\n".join(debug)
    for source_id in ("orders", "hr-people", "vault", "ext-cases", "ext-feeds"):
        assert re.search(rf"\bsource {source_id!r}", joined) or re.search(
            rf"\b{re.escape(source_id)}\b.*(static|postgres|rest)", joined
        ), f"the load lines never name source {source_id!r}:\n{joined}"


# ---------------------------------------------------------------------------
# The two things the stream must not gain.
# ---------------------------------------------------------------------------


def test_ops14_a_newline_in_a_caller_value_still_cannot_forge_a_record(
    tmp_path: Path, capture: _Capture
) -> None:
    """Every new DEBUG record goes through ``TextFormatter``/``_CONTROL_ESCAPES``.

    Measured, not assumed: the caller sends a ``purpose`` containing the text
    log's record separator and an ANSI introducer, and the count of rendered
    lines must still equal the count of records emitted.
    """
    _run(tmp_path, capture)
    text = capture.text
    assert "\x1b" not in text, "an ANSI introducer from a caller value reached the rendered log"
    emitted = len(capture.records)
    rendered = len([line for line in text.splitlines() if re.match(r"^[A-Z]+:", line)])
    assert rendered == emitted, (
        f"{emitted} records rendered as {rendered} lines: a caller-controlled "
        f"newline split a record, and the extra line is indistinguishable from "
        f"one the broker wrote itself.\n{text}"
    )
    forged = [
        line
        for line in text.splitlines()
        if line.startswith("DEBUG:nautilus.core.broker:audit chain verified")
    ]
    assert not forged, f"the caller's value forged a broker record: {forged}"


def test_ops14_no_credential_reaches_the_debug_stream(tmp_path: Path, capture: _Capture) -> None:
    """The endpoint an operator needs is present; the secret around it is not.

    ``redact_connection`` builds ``scheme://host[:port]`` by allowlist, so
    userinfo, query and fragment cannot survive into a DEBUG record.
    """
    response = _run(tmp_path, capture)
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    session_token = response.json().get("session_token") or ""
    assert session_token, "fixture minted no session token to check for"

    for name, blob in (
        ("the debug stream", capture.text),
        ("audit.jsonl", audit_text),
    ):
        for label, secret in (
            ("the DSN password", _DSN_PASSWORD),
            ("the bearer token", _BEARER_TOKEN),
            ("the query token", _QUERY_TOKEN),
            ("the session token", session_token),
        ):
            assert secret not in blob, f"{label} reached {name}"

    assert _PG_ENDPOINT in capture.text, "the endpoint an operator needs is not on the stream"
    assert _REST_ENDPOINT in capture.text, "the endpoint an operator needs is not on the stream"


def test_ops14_none_of_this_reaches_the_default_stream(tmp_path: Path, capture: _Capture) -> None:
    """A DEBUG line no operator question needs is noise; at ``info`` there is none."""
    _run(tmp_path, capture, level=logging.INFO)
    assert not capture.lines(), (
        "records emitted at DEBUG appeared on an INFO stream:\n" + "\n".join(capture.lines())
    )
    assert json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()[0])
