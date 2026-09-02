# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false, reportPrivateUsage=false
"""WAVE E17 — three source defects the wave-1 doc builders found and documented.

They were right to document rather than silently fix them; they were writing
reference pages, not repairing the broker. Fixing them is this wave's job.

1. **Approving a proposal whose rule will not load answers 500.**
   ``review.approve_proposal`` raises :class:`PromotionFailedError` when
   ``reload_rule`` rejects the rule. The route catches ``KeyError`` and
   ``AlreadyDecidedError`` and nothing else, so the reviewer gets an opaque 500
   with no hint that their rule failed to compile -- while the proposal sits in
   ``approved``, which is a state the docstring says you recover from by
   re-approving or rejecting. The reviewer cannot know that from the response.

2. **The console cannot find a decision past the first page.**
   ``ui/router.py::decision_detail`` calls ``reader.read_page()`` once and
   searches that page. Anything older reports "Decision not found" although it
   is in the log -- the REST route for the same lookup already pages the whole
   file with ``_find_audit_entry``. The console reports absence for something
   present, which is the one thing an audit console must never do.

3. **The root URL is broken in the default configuration.**
   ``GET /`` is registered unconditionally and 302s to ``/admin``. The admin
   router is mounted only ``if ui_enabled``, and ``ui.enabled`` defaults to
   False by deliberate decision. So on a default deployment the first thing
   anyone tries -- curl the root -- redirects into a 404.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

_KEY = "e17-key"


def _write_config(path: Path, *, ui_enabled: bool, audit: Path, rules_dir: bool = True) -> str:
    user_rules = path / "user-rules"
    user_rules.mkdir(exist_ok=True)
    document: dict[str, Any] = {
        "sources": [
            {
                "id": "orders",
                "type": "static",
                "description": "order rows",
                "classification": "unclassified",
                "data_types": ["orders"],
                "allowed_purposes": ["monitoring"],
                "rows": [{"order_id": 1}],
            }
        ],
        "agents": {"a": {"id": "a", "clearance": "unclassified", "default_purpose": "monitoring"}},
        "audit": {"path": str(audit)},
        "api": {"keys": [_KEY]},
        "ui": {"enabled": ui_enabled},
    }
    if rules_dir:
        # A promoted rule has to land somewhere that survives the request. The
        # shipped default configures no such directory -- which is the defect
        # below, so it has to be expressible here.
        document["rules"] = {"user_rules_dirs": [str(user_rules)]}
    cfg = path / "nautilus.yaml"
    cfg.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(cfg)


# --------------------------------------------------------------------------
# 3. The root URL in the shipped default configuration
# --------------------------------------------------------------------------


def test_e17_the_root_url_works_when_the_console_is_off(tmp_path: Path) -> None:
    """`GET /` must not send a default deployment to a 404.

    ``ui.enabled`` is False by default, so this is what every operator who
    curls the host they just deployed actually gets.
    """
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    config = _write_config(tmp_path, ui_enabled=False, audit=tmp_path / "audit.jsonl")
    with TestClient(create_app(config)) as client:
        resp = client.get("/", follow_redirects=True)

    assert resp.status_code != 404, (
        "GET / redirects to /admin, which is not mounted unless ui.enabled is "
        "true -- so the default deployment's root URL is a 404"
    )
    assert resp.status_code == 200, resp.text
    body = resp.text
    assert "/readyz" in body, "the root response should name a route that actually exists"


def test_e17_the_root_url_still_reaches_the_console_when_it_is_on(tmp_path: Path) -> None:
    """Control. Turning the console on must keep the redirect it exists for."""
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    config = _write_config(tmp_path, ui_enabled=True, audit=tmp_path / "audit.jsonl")
    with TestClient(create_app(config)) as client:
        resp = client.get("/", follow_redirects=False)

    assert resp.status_code == 302, resp.status_code
    assert resp.headers["location"] == "/admin"


# --------------------------------------------------------------------------
# 2. The console's decision lookup only sees the newest page
# --------------------------------------------------------------------------


def test_e17_the_console_finds_a_decision_older_than_one_page(tmp_path: Path) -> None:
    """A decision that is in the log must be findable in the console.

    ``DEFAULT_PAGE_SIZE`` is 50, so 60 requests puts the oldest well past the
    first page. The REST route for the same lookup pages the whole file; the
    console reads one page and calls the rest absent.
    """
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, ui_enabled=True, audit=audit)
    with TestClient(create_app(config), headers={"X-API-Key": _KEY}) as client:
        ids: list[str] = []
        for _ in range(60):
            resp = client.post(
                "/v1/request",
                json={"agent_id": "a", "intent": "show me orders", "context": {}},
            )
            assert resp.status_code == 200, resp.text
            ids.append(resp.json()["request_id"])

        oldest = ids[0]
        # The REST route already scans the whole log — this is the control that
        # proves the entry is genuinely on disk, not a fixture problem.
        rest = client.get(f"/v1/audit/{oldest}")
        assert rest.status_code == 200, (
            f"the audit entry for the oldest request is not in the log at all, "
            f"so this test would prove nothing about the console: {rest.text}"
        )

        console = client.get(f"/admin/decisions/{oldest}")
        assert console.status_code == 200, console.text
        assert "Decision not found" not in console.text, (
            "the console reports a decision as missing that the REST route "
            "just returned from the same log — decision_detail reads one page"
        )
        assert oldest in console.text


def test_e17_the_console_still_says_so_when_a_decision_really_is_absent(tmp_path: Path) -> None:
    """Control. The fix must not make every lookup succeed."""
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    config = _write_config(tmp_path, ui_enabled=True, audit=tmp_path / "audit.jsonl")
    with TestClient(create_app(config), headers={"X-API-Key": _KEY}) as client:
        client.post("/v1/request", json={"agent_id": "a", "intent": "orders", "context": {}})
        resp = client.get("/admin/decisions/no-such-request-id")

    assert "Decision not found" in resp.text, resp.text


# --------------------------------------------------------------------------
# 1. Approving a proposal whose rule will not load
# --------------------------------------------------------------------------


_LOADABLE_RULE = """
module: nautilus-routing
ruleset: e17-loadable
version: "1.0"
rules:
  - name: e17-deny-secret
    salience: 160
    when:
      - template: source
        conditions:
          - slot: id
            bind: ?sid
          - slot: classification
            expression: equals(secret)
    then:
      action: deny
      reason: "secret sources are denied"
      assert:
        - template: denial_record
          slots:
            source_id: "?sid"
            reason: "secret sources are denied"
            rule_name: "e17-deny-secret"
"""


_UNLOADABLE_RULE = """
module: nautilus-routing
ruleset: e17-unloadable
version: "1.0"
rules:
  - name: e17-references-a-template-that-does-not-exist
    salience: 100
    when:
      - template: no_such_template_anywhere
        conditions:
          - slot: nope
            bind: ?x
    then:
      action: deny
      reason: "unreachable"
"""


def test_e17_approving_on_the_default_config_is_not_an_opaque_500(tmp_path: Path) -> None:
    """The shipped default has no rules directory, and approving said only "500".

    ``rules.user_rules_dirs`` is absent from the default config, so
    ``reload_rule`` refuses to promote -- correctly, since the rule would live
    only in this process while the proposal read ``promoted``. That refusal is
    ``PromotionFailedError``, which the route did not catch. A reviewer doing
    the documented thing on a default install got an opaque 500 and no way to
    learn that one missing config key was the whole problem.
    """
    from fastapi.testclient import TestClient

    from nautilus.rkm.lineage import LineageStore
    from nautilus.rkm.queue import ProposalQueue
    from nautilus.transport.fastapi_app import create_app

    config = _write_config(
        tmp_path, ui_enabled=False, audit=tmp_path / "audit.jsonl", rules_dir=False
    )
    app = create_app(config)
    app.state.proposal_queue = ProposalQueue(tmp_path / "queue")
    app.state.lineage_store = LineageStore(tmp_path / "lineage")

    with TestClient(app, headers={"X-API-Key": _KEY}, raise_server_exceptions=False) as client:
        submitted = client.post("/v1/rkm/queue", json={"rule_yaml": _LOADABLE_RULE})
        assert submitted.status_code == 201, submitted.text
        assert submitted.json()["status"] == "pending", (
            f"the rule was not accepted for review, so this proves nothing "
            f"about approving: {submitted.text}"
        )
        resp = client.post(
            f"/v1/rkm/queue/{submitted.json()['proposal_id']}/approve",
            headers={"X-Nautilus-Reviewer": "rev-1"},
        )

    assert resp.status_code != 500, (
        "PromotionFailedError is uncaught, so the default config answers an "
        "opaque 500 to a valid approval"
    )
    assert resp.status_code == 422, resp.status_code
    detail = json.dumps(resp.json())
    assert "user_rules_dirs" in detail, (
        f"the refusal must name the config key that fixes it: {detail}"
    )
    assert "re-approve" in detail or "retry" in detail, (
        f"the proposal is left in 'approved'; the response has to say how to "
        f"get out of it: {detail}"
    )


def test_e17_a_rule_that_cannot_compile_is_refused_at_submission(tmp_path: Path) -> None:
    """Control. Static validation is why the 500 above was never about bad rules.

    Without this, the test above looks like it might be covering unloadable
    rules, and a future change that dropped static validation would go unseen.
    """
    from fastapi.testclient import TestClient

    from nautilus.rkm.queue import ProposalQueue
    from nautilus.transport.fastapi_app import create_app

    config = _write_config(tmp_path, ui_enabled=False, audit=tmp_path / "audit.jsonl")
    app = create_app(config)
    app.state.proposal_queue = ProposalQueue(tmp_path / "queue")

    with TestClient(app, headers={"X-API-Key": _KEY}, raise_server_exceptions=False) as client:
        submitted = client.post("/v1/rkm/queue", json={"rule_yaml": _UNLOADABLE_RULE})

    assert submitted.status_code == 201, submitted.text
    assert submitted.json()["status"] == "rejected", submitted.text
    assert submitted.json()["static_ok"] is False
    assert any("no_such_template_anywhere" in e for e in submitted.json()["static_errors"]), (
        submitted.json()["static_errors"]
    )


def test_e17_a_proposal_whose_rule_does_load_still_promotes(tmp_path: Path) -> None:
    """Control. The refusal above must be about the rule, not about approving."""
    from fastapi.testclient import TestClient

    from nautilus.rkm.lineage import LineageStore
    from nautilus.rkm.queue import ProposalQueue
    from nautilus.transport.fastapi_app import create_app

    good = _LOADABLE_RULE
    config = _write_config(tmp_path, ui_enabled=False, audit=tmp_path / "audit.jsonl")
    app = create_app(config)
    app.state.proposal_queue = ProposalQueue(tmp_path / "queue")
    app.state.lineage_store = LineageStore(tmp_path / "lineage")

    with TestClient(app, headers={"X-API-Key": _KEY}, raise_server_exceptions=False) as client:
        submitted = client.post("/v1/rkm/queue", json={"rule_yaml": good})
        assert submitted.status_code == 201, submitted.text
        resp = client.post(
            f"/v1/rkm/queue/{submitted.json()['proposal_id']}/approve",
            headers={"X-Nautilus-Reviewer": "rev-1"},
        )

    assert resp.status_code == 200, resp.text
