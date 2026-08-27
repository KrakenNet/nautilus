"""``nautilus demo`` — the cross-agent handoff refusal, with nothing installed.

The README calls session-aware routing the key differentiator and names the
cross-agent handoff refusal as its headline example. Until this command, the
only place that refusal ran was a journey test gated on a live Postgres: a new
user could install nautilus, follow getting-started end to end, and never see
the thing the project leads with.

The demo needs no config, no adapter, no database and no network: a handoff
declaration is a reasoning-only path (design §3.6), so the whole run is two
agents, two clearances and the built-in rule pack.
"""

from __future__ import annotations

import argparse
import asyncio
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from nautilus.core.models import HandoffDecision

# Three clearances, no sources. The classification hierarchy is built in, so
# this is the whole world the demo needs.
_AGENTS: dict[str, dict[str, str]] = {
    "chief": {"id": "chief", "clearance": "secret"},
    "analyst": {"id": "analyst", "clearance": "confidential"},
    "intern": {"id": "intern", "clearance": "unclassified"},
}


def add_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    """Add the ``demo`` command to the top-level subparsers."""
    sub.add_parser(
        "demo",
        help="Run a governed agent-to-agent handoff decision. No config or database needed.",
    )


def dispatch(args: argparse.Namespace) -> int:
    """Run the demo. Returns the process exit code."""
    del args
    with tempfile.TemporaryDirectory(prefix="nautilus-demo-") as tmp:
        return _run(Path(tmp))


def _run(workdir: Path) -> int:
    from nautilus.core.broker import Broker

    config = workdir / "nautilus.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                # A handoff declaration touches no adapter, so the demo needs
                # no sources at all -- the key is required, not the content.
                "sources": [],
                "agents": _AGENTS,
                "audit": {"path": str(workdir / "audit.jsonl")},
            }
        ),
        encoding="utf-8",
    )

    handoffs = (
        ("analyst", "chief", "confidential"),
        ("chief", "intern", "secret"),
    )

    async def _decide() -> list[HandoffDecision]:
        async with await Broker.afrom_config(config) as broker:
            return [
                await broker.declare_handoff(
                    source_agent_id=source,
                    receiving_agent_id=receiver,
                    session_id="demo",
                    data_classifications=[label],
                )
                for source, receiver, label in handoffs
            ]

    print("nautilus demo — one agent hands data to another, and the broker decides.\n")
    for (source, receiver, label), decision in zip(handoffs, asyncio.run(_decide()), strict=True):
        _print_decision(source, receiver, label, decision)

    audit_lines = (workdir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    print(f"Both decisions were signed and appended to an audit log ({len(audit_lines)} entries).")
    print("Every request the broker answers is recorded the same way.\n")
    print("Next: 'nautilus init' writes a nautilus.yaml you can serve, and")
    print("      'nautilus serve' runs it as a REST or MCP endpoint.")
    return 0


def _print_decision(source: str, receiver: str, label: str, decision: HandoffDecision) -> None:
    """Print one handoff decision the way an operator would want to read it."""
    verdict = "ALLOWED" if decision.action == "allow" else "DENIED"
    print(
        f"  {source} ({_AGENTS[source]['clearance']}) hands {label} data to "
        f"{receiver} ({_AGENTS[receiver]['clearance']})"
    )
    print(f"    handoff {verdict}")
    for record in decision.denial_records:
        print(f"    reason: {record.reason}")
        print(f"    rule:   {record.rule_name}")
    print()


__all__ = ["add_subparser", "dispatch"]
