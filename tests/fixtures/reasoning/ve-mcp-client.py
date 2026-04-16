"""VE2b — MCP stdio tool-call round-trip client (Task 5.3).

Spawns a co-located ``nautilus serve --transport mcp --mcp-mode stdio``
subprocess against the VE config, drives one ``nautilus_request`` tool
call via :class:`mcp.ClientSession`, and asserts:

1. The MCP response unwraps cleanly into a :class:`BrokerResponse`.
2. Exactly one new line was appended to ``./ve-runtime/ve-audit.jsonl``
   per tool call (NFR-15 — 1:1 tool-call -> audit-entry ratio).
3. The audit line carries the request agent verbatim (AC-13.3).

Two invocations are issued back-to-back so the D-10 / UQ-4 session-id
fallback is exercised on both branches:

* Without ``context.session_id`` -> stdio request_id branch.
* With ``context.session_id`` set explicitly -> caller-asserted branch.

Note on ``session_id_source`` audit field (documented gap, non-blocking):
the MCP server stamps ``ctx_dict["session_id_source"]`` per the D-10
fallback, but :class:`Broker` does not yet copy that key into the
:class:`AuditEntry` (its docstring explicitly says ``"once the broker
honors the field"``). Until that wiring lands, the audit line carries
``session_id_source: null``. We assert what is verifiable today
(the request reached the broker, exactly one audit line was emitted,
the agent_id is verbatim) and capture the gap in stderr instead of
hard-failing — same pattern VE2a used for the not-yet-wired escalation
accumulation rules.

Exit codes:
* 0 - all assertions passed; prints ``VE2b_MCP_PASS``.
* 1 - any assertion failed; prints a clear ``VE2b_MCP_FAIL: <reason>``
  on stderr and re-raises so the traceback survives in the VE log.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, cast

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from nautilus.core.models import BrokerResponse

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_PATH = _REPO_ROOT / "tests" / "fixtures" / "ve-config.yaml"
_AUDIT_PATH = _REPO_ROOT / "ve-runtime" / "ve-audit.jsonl"
_NAUTILUS_AUDIT_KEY = "nautilus_audit_entry"


def _count_audit_lines() -> int:
    """Return the number of non-empty lines in the VE audit JSONL."""
    if not _AUDIT_PATH.exists():
        return 0
    with _AUDIT_PATH.open("r", encoding="utf-8") as fh:
        return sum(1 for ln in fh if ln.strip())


def _read_last_audit_line() -> dict[str, Any]:
    """Return the parsed nested Nautilus AuditEntry from the last JSONL line."""
    raw_lines = [ln for ln in _AUDIT_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not raw_lines:
        raise AssertionError(f"audit file at {_AUDIT_PATH} contains no lines")
    outer = cast(dict[str, Any], json.loads(raw_lines[-1]))
    metadata = cast(dict[str, Any], outer.get("metadata") or {})
    nested_raw = metadata.get(_NAUTILUS_AUDIT_KEY)
    if not isinstance(nested_raw, str):
        raise AssertionError(
            f"last audit line missing metadata.{_NAUTILUS_AUDIT_KEY}; outer keys={list(outer)!r}"
        )
    return cast(dict[str, Any], json.loads(nested_raw))


def _wait_for_new_lines(before: int, expected_delta: int, timeout_s: float = 5.0) -> int:
    """Poll the audit file until ``count - before == expected_delta`` (or timeout)."""
    deadline = time.monotonic() + timeout_s
    after = _count_audit_lines()
    while time.monotonic() < deadline and (after - before) < expected_delta:
        time.sleep(0.1)
        after = _count_audit_lines()
    return after


async def _call_tool(
    session: ClientSession,
    *,
    agent_id: str,
    intent: str,
    context: dict[str, Any],
) -> BrokerResponse:
    """Issue one ``nautilus_request`` tool call and parse the result."""
    result = await session.call_tool(
        "nautilus_request",
        {"agent_id": agent_id, "intent": intent, "context": context},
    )
    if result.isError:
        raise AssertionError(f"nautilus_request returned isError=True: {result.content!r}")
    # FastMCP returns the Pydantic-typed result under ``structuredContent``
    # for tools annotated with a Pydantic return type. Fall back to scanning
    # ``content`` for the first JSON text block if structuredContent is None.
    payload: Any = result.structuredContent
    if payload is None:
        for block in result.content or []:
            text = getattr(block, "text", None)
            if isinstance(text, str) and text.strip().startswith("{"):
                payload = json.loads(text)
                break
    if payload is None:
        raise AssertionError(f"no parseable BrokerResponse payload in result: {result!r}")
    return BrokerResponse.model_validate(payload)


async def _main() -> int:
    """Drive two tool calls and run the post-conditions; return process exit code."""
    if not _CONFIG_PATH.is_file():
        print(f"VE2b_MCP_FAIL: config not found at {_CONFIG_PATH}", file=sys.stderr)
        return 1

    # The stdio subprocess inherits VE_PG_DSN / VE_API_KEY / VE_ES_URL from
    # this parent shell environment — the CI invocation (run.sh) exports
    # them before launching the script.
    env = dict(os.environ)
    missing = [k for k in ("VE_PG_DSN", "VE_API_KEY", "VE_ES_URL") if not env.get(k)]
    if missing:
        print(f"VE2b_MCP_FAIL: missing env vars: {missing}", file=sys.stderr)
        return 1

    params = StdioServerParameters(
        command="uv",
        args=[
            "run",
            "nautilus",
            "serve",
            "--transport",
            "mcp",
            "--mcp-mode",
            "stdio",
            "--config",
            str(_CONFIG_PATH.relative_to(_REPO_ROOT)).replace("\\", "/"),
        ],
        env=env,
        cwd=str(_REPO_ROOT),
    )

    audit_before = _count_audit_lines()

    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        if "nautilus_request" not in names:
            print(
                f"VE2b_MCP_FAIL: nautilus_request not registered; tools={sorted(names)!r}",
                file=sys.stderr,
            )
            return 1

        # --- Call 1: NO context.session_id -> stdio request_id branch ----
        resp_no_session = await _call_tool(
            session,
            agent_id="orch-a",
            intent="query vulns",
            context={"clearance": "secret", "purpose": "threat-hunt"},
        )
        if resp_no_session.request_id == "":
            raise AssertionError("BrokerResponse.request_id is empty (call 1)")

        # --- Call 2: context.session_id supplied -> caller-asserted branch -
        resp_with_session = await _call_tool(
            session,
            agent_id="orch-a",
            intent="query vulns",
            context={
                "session_id": "ve-mcp-1",
                "clearance": "secret",
                "purpose": "threat-hunt",
            },
        )
        if resp_with_session.request_id == "":
            raise AssertionError("BrokerResponse.request_id is empty (call 2)")

    # The stdio session is closed by the time we reach here, so the
    # subprocess has flushed its audit file. Poll briefly for filesystem
    # buffering on Windows/MSYS — FileSink fsyncs each emit, but the
    # subprocess shutdown can race the parent's read.
    audit_after = _wait_for_new_lines(
        before=audit_before,
        expected_delta=2,
        timeout_s=5.0,
    )
    delta = audit_after - audit_before
    if delta != 2:
        raise AssertionError(
            f"expected exactly 2 new audit lines for 2 tool calls (NFR-15); "
            f"got delta={delta} (before={audit_before}, after={audit_after})"
        )

    # Verify the LAST audit line corresponds to call 2 (context.session_id).
    last_entry = _read_last_audit_line()
    if last_entry.get("agent_id") != "orch-a":
        raise AssertionError(
            f"expected last audit agent_id='orch-a' (verbatim, AC-13.3); "
            f"got {last_entry.get('agent_id')!r}"
        )
    if last_entry.get("session_id") != "ve-mcp-1":
        raise AssertionError(
            f"expected last audit session_id='ve-mcp-1' (caller-asserted); "
            f"got {last_entry.get('session_id')!r}"
        )

    # session_id_source — Broker does not yet copy ctx_dict['session_id_source']
    # into AuditEntry (mcp_server.py docstring: 'once the broker honors the
    # field'). Document the value we observe; do not hard-fail.
    observed_source = last_entry.get("session_id_source")
    if observed_source is not None and observed_source != "context":
        raise AssertionError(f"unexpected session_id_source on context branch: {observed_source!r}")
    print(
        f"VE2b_MCP note: audit.session_id_source={observed_source!r} "
        "(expected 'context'/'stdio_request_id' once broker honors the field; "
        "currently null — pending broker wiring)",
        file=sys.stderr,
    )

    print("VE2b_MCP_PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(_main()))
    except AssertionError as exc:
        print(f"VE2b_MCP_FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
