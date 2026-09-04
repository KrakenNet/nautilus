# pyright: reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false
"""WAVE E23 — four answers that told the operator the wrong thing.

* `rkm queue submit` printed `OK:` -- the CLI's success prefix -- on the path
  that returns 1, so a rejected proposal read as success to a script grepping
  the prefix and as failure to one checking `$?`.
* `rkm queue approve` reported every 409 as `already_approved` and exited 0, even
  when the standing decision was a *rejection*. `rkm queue reject` answered the
  mirror-image case with exit 1 unconditionally. The same condition got opposite
  answers depending on which verb you used, and one of them was a lie.
* `adapters list --url` ran `raise_for_status()` inside the `except` that catches
  transport errors, so a broker that answered fine and refused the credential was
  reported as `could not reach {url}` -- sending the operator to check DNS, the
  firewall, and whether the process was even up.
* Two 404s built their body from `str(KeyError(...))`. `KeyError.__str__` is
  `repr(args[0])`, so a message that already reads well came back wrapped in a
  second layer of quotes: `{"detail": "\"proposal not found: 'prop_x'\""}`.
  A client that prints `detail` prints the quotes. `/v1/rules/{name}/retract`
  was already correct and is the control.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import yaml

if TYPE_CHECKING:
    from nautilus.rkm.types import ProposalStatus

pytestmark = [pytest.mark.integration]

_AUTH = {"X-API-Key": "secret-key", "X-Nautilus-Reviewer": "alice"}

_BAD_RULE = "name: bad-rule\nsalience: 10\nwhen: []\nthen: []\n"


# ---------------------------------------------------------------------------
# 1 -- OK: on a path that fails
# ---------------------------------------------------------------------------


def test_e23_a_rejected_submit_does_not_claim_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The pin. The success prefix and the exit code must agree about one run."""
    from nautilus.cli import rkm as rkm_cli

    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice")
    monkeypatch.chdir(tmp_path)
    rule = tmp_path / "bad.yaml"
    rule.write_text(_BAD_RULE, encoding="utf-8")

    code = rkm_cli._cmd_queue_submit(
        argparse.Namespace(
            rkm_subcommand="queue",
            rkm_queue_subcommand="submit",
            file=str(rule),
            json=False,
            config=None,
        )
    )
    out = capsys.readouterr()

    assert code == 1, f"a rejected proposal must exit 1, got {code}"
    assert "rejected" in (out.out + out.err), out.out + out.err
    assert "OK:" not in out.out, (
        f"the run exited 1 and printed the success prefix, so a script grepping "
        f"`OK:` and a script checking `$?` disagree about it: {out.out!r}"
    )


def test_e23_an_accepted_submit_still_says_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control. The prefix must track the verdict, not disappear."""
    from nautilus.cli import rkm as rkm_cli
    from nautilus.rkm.types import Proposal

    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice")
    monkeypatch.chdir(tmp_path)
    rule = tmp_path / "ok.yaml"
    rule.write_text(_BAD_RULE, encoding="utf-8")

    accepted = Proposal(
        proposal_id="prop_ok",
        schema_version=2,
        status="pending",
        proposer="pipeline",
        proposed_at=datetime.now(UTC),
        target_module="nautilus-routing",
        artifact={"yaml": _BAD_RULE},
        artifact_type="rule",
        validation={"confidence": 0.9, "static_ok": True, "static_errors": []},
        lineage={},
        decisions=[],
    )

    def _accepted(*args: Any, **kwargs: Any) -> Proposal:  # noqa: ARG001
        return accepted

    monkeypatch.setattr("nautilus.rkm.validator.pipeline.run_pipeline", _accepted)

    code = rkm_cli._cmd_queue_submit(
        argparse.Namespace(
            rkm_subcommand="queue",
            rkm_queue_subcommand="submit",
            file=str(rule),
            json=False,
            config=None,
        )
    )
    out = capsys.readouterr()

    assert code == 0, out.out + out.err
    assert "OK:" in out.out, out.out


# ---------------------------------------------------------------------------
# 2 -- approve and reject disagreed about the same condition
# ---------------------------------------------------------------------------


def _seed(tmp_path: Path, status: ProposalStatus) -> None:
    from nautilus.rkm.queue import ProposalQueue
    from nautilus.rkm.types import Proposal

    ProposalQueue(tmp_path / ".nautilus/rkm/queue").submit(
        Proposal(
            proposal_id="prop_x",
            schema_version=2,
            status=status,
            proposer="pipeline",
            proposed_at=datetime.now(UTC),
            target_module="nautilus-routing",
            artifact={"yaml": _BAD_RULE},
            artifact_type="rule",
            validation={},
            lineage={},
            decisions=[],
        )
    )


def _reject(tmp_path: Path) -> int:
    from nautilus.cli import rkm as rkm_cli

    return rkm_cli._cmd_queue_reject(
        argparse.Namespace(
            rkm_subcommand="queue",
            rkm_queue_subcommand="reject",
            proposal_id="prop_x",
            reason="not wanted",
            json=False,
            config=None,
            url=None,
        )
    )


def test_e23_rejecting_an_already_rejected_proposal_is_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The pin. The state you asked for already holds, so the verb succeeded."""
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice")
    monkeypatch.chdir(tmp_path)
    _seed(tmp_path, "rejected")

    code = _reject(tmp_path)
    out = capsys.readouterr()

    assert code == 0, (
        f"rejecting an already-rejected proposal exited {code}, while approving an "
        f"already-approved one exited 0 -- the same condition, opposite answers: "
        f"{(out.out + out.err).strip()}"
    )
    assert "already rejected" in out.out, out.out


def test_e23_rejecting_a_promoted_proposal_still_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control. Idempotency is not "always succeed" — a conflict must still fail.

    ``promoted``, not ``approved``: ``reject_proposal`` accepts ``approved`` on
    purpose, because backing out an approval whose promotion failed is the only
    way out of that state. ``promoted`` is terminal.
    """
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice")
    monkeypatch.chdir(tmp_path)
    _seed(tmp_path, "promoted")

    code = _reject(tmp_path)
    out = capsys.readouterr()

    assert code == 1, out.out + out.err
    assert "promoted" in (out.out + out.err), (
        f"the refusal has to name the decision that stands: {(out.out + out.err).strip()}"
    )


def _approve_against_409(monkeypatch: pytest.MonkeyPatch, current_status: str) -> tuple[int, str]:
    import httpx

    from nautilus.cli import rkm as rkm_cli

    class _Client:
        """``_cmd_queue_approve`` dials through ``httpx.Client``, not ``httpx.post``."""

        def __init__(self, *args: Any, **kwargs: Any) -> None: ...

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: Any) -> None: ...

        def post(self, *args: Any, **kwargs: Any) -> httpx.Response:  # noqa: ARG002
            return httpx.Response(
                409,
                json={"detail": {"error": "already_decided", "current_status": current_status}},
                request=httpx.Request("POST", "http://broker/v1/rkm/queue/prop_x/approve"),
            )

    monkeypatch.setattr(httpx, "Client", _Client)
    code = rkm_cli._cmd_queue_approve(
        argparse.Namespace(
            rkm_subcommand="queue",
            rkm_queue_subcommand="approve",
            proposal_id="prop_x",
            json=False,
            config=None,
            url="http://broker",
            api_key=None,
        )
    )
    return code, current_status


def test_e23_approving_a_rejected_proposal_is_not_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The pin. It answered every 409 with `already_approved` and exit 0."""
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice")
    code, _ = _approve_against_409(monkeypatch, "rejected")
    out = capsys.readouterr()

    assert code == 1, (
        f"approving a proposal that stands *rejected* exited {code} and reported "
        f"'already_approved': {(out.out + out.err).strip()}"
    )
    assert "rejected" in (out.out + out.err), (out.out + out.err).strip()


def test_e23_approving_an_approved_proposal_is_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control. The genuinely idempotent case must stay exit 0."""
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice")
    code, _ = _approve_against_409(monkeypatch, "approved")
    out = capsys.readouterr()

    assert code == 0, (out.out + out.err).strip()
    assert "already approved" in out.out, out.out


# ---------------------------------------------------------------------------
# 3 -- a refused credential reported as an unreachable host
# ---------------------------------------------------------------------------


def test_e23_a_401_is_not_reported_as_unreachable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The pin. `raise_for_status()` inside the transport `except` misclassified it."""
    import httpx

    from nautilus.cli import adapters as adapters_cli

    def _fake_get(*args: Any, **kwargs: Any) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(
            401,
            json={"detail": "Not authenticated"},
            request=httpx.Request("GET", "http://broker/v1/adapters"),
        )

    monkeypatch.setattr(httpx, "get", _fake_get)
    rows = adapters_cli._remote_adapters("http://broker", None)
    out = capsys.readouterr()

    assert rows is None
    message = (out.out + out.err).lower()
    assert "could not reach" not in message, (
        f"the broker answered; it refused the credential. Reporting it as "
        f"unreachable sends the operator to DNS and the firewall: {message.strip()}"
    )
    assert "401" in message, message.strip()


def test_e23_a_real_transport_failure_still_says_unreachable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control. A host that really is unreachable must still say so."""
    import httpx

    from nautilus.cli import adapters as adapters_cli

    def _boom(*args: Any, **kwargs: Any) -> httpx.Response:  # noqa: ARG001
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "get", _boom)
    assert adapters_cli._remote_adapters("http://broker", None) is None
    out = capsys.readouterr()

    assert "could not reach" in (out.out + out.err).lower(), (out.out + out.err).strip()


# ---------------------------------------------------------------------------
# 4 -- 404 bodies that were a quoted bare id
# ---------------------------------------------------------------------------


def _config(path: Path) -> str:
    document: dict[str, Any] = {
        "sources": [
            {
                "id": "orders",
                "type": "static",
                "description": "order rows",
                "classification": "unclassified",
                "data_types": ["orders"],
                "rows": [{"order_id": 1}],
            }
        ],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(path / "audit.jsonl")},
        "api": {"keys": ["secret-key"]},
    }
    config = path / "nautilus.yaml"
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(config)


@pytest.mark.parametrize(
    ("path", "body", "noun", "name"),
    [
        ("/v1/rkm/queue/prop_missing/approve", {}, "proposal", "prop_missing"),
        (
            "/v1/rkm/queue/prop_missing/reject",
            {"reason": "no"},
            "proposal",
            "prop_missing",
        ),
        (
            "/v1/rules/rule_missing/retract",
            {"reason": "no", "yes": True},
            "rule",
            "rule_missing",
        ),
    ],
    ids=["approve", "reject", "retract"],
)
def test_e23_a_404_says_what_was_not_found(
    tmp_path: Path, path: str, body: dict[str, Any], noun: str, name: str
) -> None:
    """`KeyError.__str__` is `repr(args[0])`, so the message gains a layer of quotes.

    `retract` is the control: it never went through `str(exc)` and was already
    right, so it must stay right.
    """
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    with TestClient(create_app(_config(tmp_path))) as client:
        resp = client.post(path, headers=_AUTH, json=body)

    assert resp.status_code == 404, resp.text
    detail = resp.json()["detail"]
    assert isinstance(detail, str), detail
    assert not (detail[:1] in "\"'" and detail[-1:] in "\"'"), (
        f"the body is a quoted string inside a quoted string -- str(KeyError(...)) "
        f"re-quotes a message that already read fine, and a client that prints "
        f"detail prints the quotes: {json.dumps(resp.json())}"
    )
    assert noun in detail and "not found" in detail, detail
    assert name in detail, detail
