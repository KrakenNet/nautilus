"""Every transport that reaches the broker must say who is calling.

``caller=`` keys the cumulative-exposure ledger. When only REST passed it, the
same client presenting the same API key to the MCP port accumulated into a
different ledger and escaped escalation by switching transport -- a fail-quiet
default that a reader of ``fastapi_app.py`` alone could not see.

This is a source-shape guard, deliberately: the defect is a *missing* call at a
site that does not exist yet. A behavioural test can only cover the transports
someone remembered to write one for, which is how the gap shipped.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SURFACES = (Path("nautilus/transport"), Path("nautilus/ui"))
_ROOT = Path(__file__).resolve().parents[3]


def _arequest_calls() -> list[tuple[str, int, ast.Call]]:
    found: list[tuple[str, int, ast.Call]] = []
    for surface in _SURFACES:
        for path in sorted((_ROOT / surface).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "arequest"
                ):
                    found.append((str(path.relative_to(_ROOT)), node.lineno, node))
    return found


@pytest.mark.unit
def test_every_transport_passes_caller_to_arequest() -> None:
    """A transport calling ``arequest`` without ``caller=`` keys its own ledger."""
    calls = _arequest_calls()
    assert calls, "control failed: no arequest call sites found, so this guard checks nothing"

    missing = [
        f"{path}:{lineno}"
        for path, lineno, node in calls
        if not any(kw.arg == "caller" for kw in node.keywords)
    ]
    assert not missing, (
        f"these transports call Broker.arequest without caller=: {missing}. "
        f"Without it the request keys an agent-id-only exposure ledger, so a "
        f"caller resets its cumulative exposure by switching transport. Pass "
        f"nautilus.transport.auth.caller_identity(request, auth_mode=...), or "
        f"None explicitly when the transport genuinely has no caller identity "
        f"(MCP stdio: the parent process owns the pipe)."
    )
