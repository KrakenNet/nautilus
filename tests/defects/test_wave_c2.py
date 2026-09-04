"""One pin per Wave C2 item — the first five minutes after ``pip install``.

C2 is the demo that shows the differentiator without a database, C3 is the
mandatory ``setup()`` that appeared in no doc, C4 is ``nautilus init`` plus the
``serve --config`` default the CLI reference already promised, C9 is two
required source fields that need not be, and C10 is the in-memory adapter the
project ships in a template but not as a source type — so the fastest path to a
working broker is still "hand-transcribe an adapter class".
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.defect


_ROWS: list[dict[str, Any]] = [
    {"order_id": 1001, "user_id": 42, "total": 19.99},
    {"order_id": 1002, "user_id": 43, "total": 7.50},
]

_STATIC_SOURCE: dict[str, Any] = {
    "id": "orders",
    "type": "static",
    "classification": "unclassified",
    "data_types": ["orders"],
    "rows": _ROWS,
}


def _write(tmp_path: Path, config: dict[str, Any]) -> str:
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return str(path)


# ===========================================================================
# C2 -- the differentiator has no runnable surface
# ===========================================================================


def test_c2_demo_shows_a_governed_refusal_with_no_config_and_no_database(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``pip install`` then one command has to reach something worth seeing.

    Today the cross-agent handoff refusal — the README's own key
    differentiator — runs in exactly one place: a journey test gated on a live
    Postgres. Nothing a new user can type reaches it.
    """
    from nautilus.cli import main

    monkeypatch.chdir(tmp_path)
    code = main(["demo"])
    out = capsys.readouterr().out

    assert code == 0, out
    lowered = out.lower()
    assert "handoff" in lowered, out
    assert "deny" in lowered or "denied" in lowered, out
    assert "secret" in lowered and "unclassified" in lowered, out
    assert "information-flow-violation" in lowered, (
        f"the demo does not name the rule that refused the handoff:\n{out}"
    )
    assert list(tmp_path.iterdir()) == [], (
        f"the demo left files behind in the working directory: {list(tmp_path.iterdir())}"
    )


def test_c2_getting_started_leads_with_the_handoff_not_an_adapter() -> None:
    """The refusal needs no adapter, so it does not belong behind one."""
    text = Path("docs/getting-started.md").read_text(encoding="utf-8")

    assert "nautilus demo" in text, "getting-started never mentions the demo command"
    assert "## Configuration" in text
    assert text.index("nautilus demo") < text.index("## Configuration"), (
        "the demo is documented after the config section it does not need"
    )
    assert "nautilus demo" in Path("README.md").read_text(encoding="utf-8"), (
        "the README's key-differentiator section still has no runnable surface"
    )


# ===========================================================================
# C3 -- setup() is mandatory and undocumented
# ===========================================================================


def test_c3_the_docs_say_what_setup_is_for() -> None:
    """A Postgres session store whose schema was never created fails at request time.

    ``Broker.setup()`` is what creates it, and it appeared in no document —
    neither in getting-started nor in the operator guide's own session-store
    section.
    """
    operator = Path("docs/how-to/operator-guide.md").read_text(encoding="utf-8")
    started = Path("docs/getting-started.md").read_text(encoding="utf-8")

    assert "setup()" in operator, "the operator guide never mentions Broker.setup()"
    assert "setup()" in started, "getting-started never mentions setup()"
    assert "afrom_config" in operator, (
        "the operator guide does not say how the async path gets its setup() call"
    )


# ===========================================================================
# C4 -- no scaffold, and a --config default the docs already promise
# ===========================================================================


def test_c4_init_writes_a_config_the_broker_can_load_and_answer_from(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The CLI scaffolds adapter packages but not the one file every user needs."""
    from nautilus.cli import main
    from nautilus.core.broker import Broker

    monkeypatch.chdir(tmp_path)
    code = main(["init"])
    out = capsys.readouterr().out
    assert code == 0, out

    written = tmp_path / "nautilus.yaml"
    assert written.is_file(), f"init wrote no nautilus.yaml: {list(tmp_path.iterdir())}"

    with Broker.from_config(written) as broker:
        response = broker.request(
            "agent-alpha",
            "recent orders",
            {"purpose": "support", "session_id": "s1"},
        )
    assert response.outcome == "allowed", (
        f"the scaffolded config does not answer its own example request: "
        f"{response.outcome} {response.denial_records} {response.skip_records}"
    )
    assert response.data, "the scaffolded config routed but returned nothing"


def test_c4_init_refuses_to_overwrite_an_existing_config(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: a scaffold that clobbers a real config is worse than no scaffold."""
    from nautilus.cli import main

    monkeypatch.chdir(tmp_path)
    existing = tmp_path / "nautilus.yaml"
    existing.write_text("# mine\n", encoding="utf-8")

    code = main(["init"])
    capsys.readouterr()

    assert code != 0, "init overwrote an existing config and reported success"
    assert existing.read_text(encoding="utf-8") == "# mine\n"


def test_c4_serve_defaults_to_the_config_the_cli_reference_promises() -> None:
    """``docs/reference/cli.md`` documents ``--config`` default ``nautilus.yaml``.

    argparse marks it ``required=True``, so the documented default does not
    exist and ``nautilus serve`` in a configured directory is an error.
    """
    from nautilus.cli import _build_parser  # pyright: ignore[reportPrivateUsage]

    args = _build_parser().parse_args(["serve"])
    assert args.config == "nautilus.yaml", args.config


# ===========================================================================
# C9 -- two required fields that need not be
# ===========================================================================


def test_c9_a_source_needs_neither_a_description_nor_a_connection() -> None:
    """Both are required, and neither is load-bearing for a source with rows."""
    from nautilus.config.models import SourceConfig

    source = SourceConfig(
        id="orders",
        type="static",
        classification="unclassified",
        data_types=["orders"],
        rows=_ROWS,
    )
    assert source.description == ""
    assert source.connection == ""


def test_c9_a_source_that_dials_out_still_needs_a_connection() -> None:
    """Control: making the field optional must not make a broken source load.

    A postgres source with no DSN is the failure Wave A moved to startup; a
    default must not move it back to request time.
    """
    import pydantic

    from nautilus.config.models import SourceConfig

    with pytest.raises(pydantic.ValidationError, match="connection"):
        SourceConfig(
            id="db",
            type="postgres",
            classification="unclassified",
            data_types=["orders"],
            table="public.orders",
        )


# ===========================================================================
# C10 -- the in-memory adapter ships in a template, not as a source type
# ===========================================================================


def test_c10_a_static_source_answers_a_request_from_rows_in_the_config(
    tmp_path: Path,
) -> None:
    """Getting-started asks a new user to transcribe an adapter class by hand.

    The code for it is already in the repo — the ``adapters new`` template
    ships an in-memory adapter with scope enforcement. It needs a source type
    and a registry entry.
    """
    from nautilus.core.broker import Broker

    config = _write(
        tmp_path,
        {
            "sources": [_STATIC_SOURCE],
            "agents": {"agent-alpha": {"id": "agent-alpha", "clearance": "unclassified"}},
            "audit": {"path": str(tmp_path / "audit.jsonl")},
        },
    )
    with Broker.from_config(config) as broker:
        response = broker.request("agent-alpha", "recent orders", {"purpose": "support"})

    assert response.outcome == "allowed", (
        f"{response.outcome}: {response.denial_records} {response.skip_records}"
    )
    assert response.data["orders"] == _ROWS, response.data


def test_c10_a_static_source_enforces_the_scope_it_is_given() -> None:
    """A source that ignores scope constraints is a source that over-returns.

    Same contract every other adapter is held to: enforce what you understand,
    fail closed on what you do not.
    """
    from nautilus.adapters import ADAPTER_REGISTRY
    from nautilus.adapters.base import ScopeEnforcementError
    from nautilus.config.models import SourceConfig
    from nautilus.core.models import IntentAnalysis, ScopeConstraint

    assert "static" in ADAPTER_REGISTRY, sorted(ADAPTER_REGISTRY)
    adapter = ADAPTER_REGISTRY["static"]()
    config = SourceConfig(
        id="orders",
        type="static",
        classification="unclassified",
        data_types=["orders"],
        rows=_ROWS,
    )
    intent = IntentAnalysis(raw_intent="recent orders", data_types_needed=["orders"], entities=[])

    async def _run() -> Any:
        await adapter.connect(config)
        try:
            scoped = await adapter.execute(
                intent,
                [ScopeConstraint(source_id="orders", field="user_id", operator="=", value=42)],
                {},
            )
            with pytest.raises(ScopeEnforcementError):
                await adapter.execute(
                    intent,
                    [
                        ScopeConstraint(
                            source_id="orders",
                            field="total",
                            operator="BETWEEN",
                            value=[1, 10],
                        )
                    ],
                    {},
                )
            return scoped
        finally:
            await adapter.close()

    scoped = asyncio.run(_run())
    assert [row["order_id"] for row in scoped.rows] == [1001], scoped.rows
