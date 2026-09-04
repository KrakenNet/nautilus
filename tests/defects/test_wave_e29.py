"""WAVE E29 — the CodeQL sweep over the 1.0 branch.

Three of the alerts were real, and each is pinned here:

1. **Path traversal on a proposal id.** ``GET /v1/rkm/proposals/{proposal_id}``
   takes the id off the URL and ``ProposalQueue`` interpolates it straight into
   a filename, so ``../../etc/passwd`` reached ``open()``.
2. **A live credential written world-readable.** ``nautilus init`` wrote
   ``nautilus.yaml`` with ``Path.write_text``, which creates at the umask
   default — 0644 on every distro the docs name — and the file holds a freshly
   minted API key.
3. **The same key echoed to stdout.** The scaffold printed a ready-to-paste
   ``curl`` line with the secret in it, so the key landed in scrollback, in CI
   logs and in any screen share of a first run.

The two ``py/stack-trace-exposure`` alerts on ``/admin/api/query`` are here
too: the sink's ``OSError`` carries the audit log's absolute path, and an
unhandled exception carries whatever the driver said. Both answered a browser.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

_KEY = "e29-key"
_SOURCE: dict[str, Any] = {
    "id": "orders",
    "type": "static",
    "classification": "unclassified",
    "data_types": ["orders"],
    "rows": [{"id": 1, "region": "us-east"}],
}


def _config(tmp_path: Path) -> str:
    document: dict[str, Any] = {
        "sources": [_SOURCE],
        "agents": {"a1": {"id": "a1", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "api": {"keys": [_KEY]},
        "ui": {"enabled": True},
    }
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# 1 -- a proposal id is a filename, so it must not be able to leave the queue
# ---------------------------------------------------------------------------


def test_e29_a_proposal_id_cannot_escape_the_queue_directory(tmp_path: Path) -> None:
    """A traversing id is *absent*, not a read of whatever it points at."""
    from nautilus.rkm.queue import InvalidProposalIdError, ProposalQueue

    outside = tmp_path / "secret.jsonl"
    outside.write_text('{"proposal_id": "leaked"}\n', encoding="utf-8")
    queue = ProposalQueue(tmp_path / "queue")
    # The control that this refusal is not a vacuous pass lives in the next
    # test: a generated ``prop_<hex>`` id still round-trips through this queue.

    assert queue.get("../secret") is None, (
        "ProposalQueue.get read a file outside its own directory: a proposal id "
        "arrives from the URL path of /v1/rkm/proposals/{proposal_id}."
    )
    for bad in ("..", ".", "../../etc/passwd", "a/b", "a\x00b"):
        assert queue.get(bad) is None, f"queue.get accepted {bad!r} as an id"

    # The write side refuses outright rather than answering "absent": a submit
    # that cannot name its own file has nowhere to put the proposal.
    from datetime import UTC, datetime

    from nautilus.rkm.types import Proposal

    with pytest.raises(InvalidProposalIdError):
        queue.submit(
            Proposal(
                proposal_id="../escape",
                schema_version=1,
                status="pending",
                proposer="e29",
                proposed_at=datetime.now(UTC),
                target_module="nautilus-routing",
                artifact_type="rule",
                artifact={"name": "e29-probe"},
                validation={},
                lineage={},
                decisions=[],
            )
        )
    assert not (tmp_path / "escape.jsonl").exists(), (
        "a refused submit still wrote a file outside the queue directory"
    )


def test_e29_a_legitimate_proposal_id_still_round_trips(tmp_path: Path) -> None:
    """The guard must not have closed the door on the ids the pipeline mints."""
    from datetime import UTC, datetime

    from nautilus.rkm.queue import ProposalQueue
    from nautilus.rkm.types import Proposal

    queue = ProposalQueue(tmp_path / "queue")
    proposal = Proposal(
        proposal_id="prop_0123456789abcdef0123456789abcdef",
        schema_version=1,
        status="pending",
        proposer="e29",
        proposed_at=datetime.now(UTC),
        target_module="nautilus-routing",
        artifact_type="rule",
        artifact={"name": "e29-probe"},
        validation={},
        lineage={},
        decisions=[],
    )
    queue.submit(proposal)
    read_back = queue.get(proposal.proposal_id)
    assert read_back is not None, "a generated prop_<hex> id no longer round-trips"
    assert read_back.proposal_id == proposal.proposal_id


# ---------------------------------------------------------------------------
# 2 + 3 -- the scaffolded config holds a live key
# ---------------------------------------------------------------------------


def test_e29_init_writes_the_config_readable_only_by_its_owner(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The file holds a fresh API key, so group and other must not read it."""
    from nautilus.cli import main

    assert main(["init", "--dir", str(tmp_path)]) == 0
    target = tmp_path / "nautilus.yaml"
    mode = stat.S_IMODE(os.stat(target).st_mode)
    assert mode == 0o600, f"nautilus init wrote a live credential at {mode:04o}, not 0600"


def test_e29_init_never_prints_the_key_it_generated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """stdout is scrollback, CI logs and screen shares. The file is not."""
    from nautilus.cli import main

    assert main(["init", "--dir", str(tmp_path)]) == 0
    printed = capsys.readouterr().out
    document = yaml.safe_load((tmp_path / "nautilus.yaml").read_text(encoding="utf-8"))
    keys = [str(k) for k in document["api"]["keys"]]

    # Control: the key is really in the file, so "absent from stdout" is not
    # passing because the scaffold stopped generating one.
    assert keys and len(keys[0]) >= 32, f"init wrote no usable api.keys entry: {keys!r}"
    for key in keys:
        assert key not in printed, "nautilus init echoed the generated API key to stdout"


# ---------------------------------------------------------------------------
# 4 -- the playground answers a browser, so it must not answer with our paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raised", "status"),
    [
        (OSError("[Errno 28] No space left on device: '/srv/nautilus/audit.jsonl'"), 503),
        (RuntimeError("psycopg: connection to 10.0.0.7:5432 failed: password auth"), 500),
    ],
)
def test_e29_the_playground_does_not_return_internal_exception_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raised: Exception, status: int
) -> None:
    """Neither the sink's path nor a driver's message belongs in the response."""
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    app = create_app(_config(tmp_path))
    with TestClient(app) as client:
        broker: Any = app.state.broker

        async def _boom(*_args: Any, **_kwargs: Any) -> Any:
            raise raised

        monkeypatch.setattr(broker, "arequest", _boom)
        response = client.post(
            "/admin/api/query",
            cookies={"nautilus_key": _KEY},
            json={
                "agent_id": "a1",
                "intent": "list recent orders",
                "context": {"purpose": "analytics"},
            },
        )

    assert response.status_code == status, response.text
    body = response.text
    for leaked in ("/srv/nautilus", "Errno 28", "10.0.0.7", "psycopg", "password auth"):
        assert leaked not in body, f"the playground returned {leaked!r} to a browser client: {body}"
