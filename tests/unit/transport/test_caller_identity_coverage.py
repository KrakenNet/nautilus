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


def _calls_named(name: str) -> list[tuple[str, int, ast.Call]]:
    """Every call to ``name`` across the transport surfaces, however imported."""
    found: list[tuple[str, int, ast.Call]] = []
    for surface in _SURFACES:
        for path in sorted((_ROOT / surface).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                func = node.func if isinstance(node, ast.Call) else None
                called = (
                    func.attr
                    if isinstance(func, ast.Attribute)
                    else func.id
                    if isinstance(func, ast.Name)
                    else None
                )
                if called == name and isinstance(node, ast.Call):
                    found.append((str(path.relative_to(_ROOT)), node.lineno, node))
    return found


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


# ``caller_identity`` reads the deployment's auth configuration through these
# three arguments and nothing else. Omitting them is not a smaller answer, it is
# a *different* one: without ``keys`` the ``_match_key`` lookup is skipped
# entirely, ``agent_id`` stays ``None``, and ``None`` is the unbound case -- the
# caller names its own agent and holds every capability. ``/admin/sources``
# omitted all three and published every source's id, description, data types and
# classification to a credential whose bound agent's clearance could reach none
# of them, one URL away from the ``/v1/sources`` filter that refuses exactly
# that.
_REQUIRED_KWARGS = ("auth_mode", "keys", "agent_subjects")


@pytest.mark.unit
def test_every_caller_identity_call_reads_the_deployment_config() -> None:
    """A route resolving a caller without the key registry resolves a root one."""
    calls = [
        (path, lineno, node)
        for path, lineno, node in _calls_named("caller_identity")
        # The definition's own module re-exports it; the call sites are elsewhere.
        if path != "nautilus/transport/auth.py"
    ]
    assert calls, "control failed: no caller_identity call sites found, so this checks nothing"

    missing = {
        f"{path}:{lineno}": [
            kwarg for kwarg in _REQUIRED_KWARGS if not any(k.arg == kwarg for k in node.keywords)
        ]
        for path, lineno, node in calls
        if any(not any(k.arg == kwarg for k in node.keywords) for kwarg in _REQUIRED_KWARGS)
    }
    assert not missing, (
        f"these call sites resolve a caller without part of the deployment's auth "
        f"config: {missing}. Each missing argument silently downgrades the answer -- "
        f"no 'keys' means no bound agent_id and no capability scoping, no "
        f"'auth_mode' means a proxy_trust deployment is read as api_key, no "
        f"'agent_subjects' means a forwarded subject binds nobody. Pass all three "
        f"off app.state (see nautilus/ui/router.py) or off the broker config (see "
        f"nautilus/transport/mcp_server.py)."
    )
