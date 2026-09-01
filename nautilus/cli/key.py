"""``nautilus key`` subcommand surface (#18, #25).

Subcommands:
    key list --url URL [--api-key KEY] [--json]
    key rotate --yes --url URL [--api-key KEY] [--json]
    key revoke <kid> --reason "..." --yes --url URL [--api-key KEY] [--json]

``--url`` is REQUIRED on all three. Rotation and revocation are audited events
a *broker* emits, and a broker holds its ring in memory whether or not
``session_tokens.key_ring_path`` also persists it, so acting on the file
directly would leave the running broker signing with a key it no longer has and
write no audit event. The previous no-``--url`` mode built a throwaway
:class:`KeyRing` (whose ``__init__`` auto-mints a primary), printed a fresh
random kid and exited 0 having changed nothing on any broker.

With ``--url`` the command drives the ``GET /v1/keys/jwks.json`` /
auth-gated ``POST /v1/keys/rotate`` / ``POST /v1/keys/{kid}/revoke``
endpoints, the server emits ``signing_key_rotated`` / ``signing_key_revoked``
audit events, and in-flight session tokens keep verifying during the grace
window (agents are lazily re-signed on their next request — #25).
"""

from __future__ import annotations

import argparse
import json

import httpx

from nautilus.cli._common import API_KEY_HELP, err, fail, ok, require_reviewer, resolve_api_key

_URL_HELP = (
    "Base URL of the running broker whose signing ring to act on. Required: "
    "the ring is in-broker state and the CLI holds no copy of it."
)


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    """Add the ``--url`` / ``--api-key`` / ``--json`` trio shared by all three."""
    parser.add_argument("--url", help=_URL_HELP)
    parser.add_argument("--api-key", dest="api_key", help=API_KEY_HELP)
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout.")


def add_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    """Add ``key`` group to the top-level argparse subparsers."""
    p_key = sub.add_parser("key", help="Key management (AC-18.c / AC-18.e / #25).")
    key_sub = p_key.add_subparsers(dest="key_subcommand", metavar="subcommand")

    p_list = key_sub.add_parser("list", help="List a live broker's active keys.")
    _add_target_args(p_list)

    p_rotate = key_sub.add_parser("rotate", help="Mint new primary key (AC-18.e, #25).")
    p_rotate.add_argument("--yes", action="store_true", help="Confirm destructive operation.")
    _add_target_args(p_rotate)

    p_revoke = key_sub.add_parser("revoke", help="Revoke a key immediately.")
    p_revoke.add_argument("kid", help="Key ID to revoke.")
    p_revoke.add_argument("--reason", required=True, help="Revocation reason (required).")
    p_revoke.add_argument("--yes", action="store_true", help="Confirm destructive operation.")
    _add_target_args(p_revoke)


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``key`` invocation. Returns process exit code."""
    sub = getattr(args, "key_subcommand", None)
    if sub == "list":
        return _cmd_list(args)
    if sub == "rotate":
        return _cmd_rotate(args)
    if sub == "revoke":
        return _cmd_revoke(args)
    err("key: no subcommand given (try: list, rotate, revoke)")
    return 2


def _require_url(args: argparse.Namespace, command: str) -> str | None:
    """Return ``--url`` or ``None``, having already reported the failure."""
    url = getattr(args, "url", None)
    if url:
        return str(url).rstrip("/")
    fail(
        f"key {command}: --url is required. Rotation and revocation are audited "
        f"events the broker emits against the ring it is serving with, so there "
        f"is nothing for the CLI to act on locally — point --url at the running "
        f"broker (e.g. --url http://localhost:8000)."
    )
    return None


def _request(
    method: str,
    url: str,
    api_key: str | None,
    body: dict[str, str] | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Response:
    """Send ``method`` to ``url`` with the ``X-API-Key`` header (#25 --url mode).

    ``transport`` is injectable so unit tests can use ``httpx.MockTransport``
    without a live server.
    """
    headers = {"X-API-Key": api_key} if api_key else {}
    with httpx.Client(transport=transport, timeout=10.0) as client:
        return client.request(method, url, json=body, headers=headers)


def _call(
    args: argparse.Namespace,
    command: str,
    method: str,
    path: str,
    body: dict[str, str] | None,
    transport: httpx.BaseTransport | None,
) -> tuple[int, dict[str, object] | None]:
    """Run one broker call. Returns ``(exit_code, payload)``; payload is None on error."""
    base = _require_url(args, command)
    if base is None:
        return 2, None
    endpoint = base + path
    try:
        response = _request(method, endpoint, resolve_api_key(args), body, transport=transport)
    except httpx.HTTPError as exc:
        fail(f"key {command}: cannot reach {endpoint}: {exc}")
        return 2, None
    if response.status_code != 200:
        err(f"key {command}: server returned {response.status_code}: {response.text}")
        return 2, None
    return 0, response.json()


def _cmd_list(args: argparse.Namespace, *, transport: httpx.BaseTransport | None = None) -> int:
    code, payload = _call(args, "list", "GET", "/v1/keys/jwks.json", None, transport)
    if payload is None:
        return code
    keys = payload.get("keys") or []
    if getattr(args, "json", False):
        print(json.dumps(keys))
        return 0
    if not keys:
        print("no active keys (session tokens are disabled on this broker)")
        return 0
    for key in keys:
        entry: dict[str, object] = key  # type: ignore[assignment]
        print(f"  {entry.get('kid')}  kty={entry.get('kty')}  use={entry.get('use')}")
    return 0


def _cmd_rotate(args: argparse.Namespace, *, transport: httpx.BaseTransport | None = None) -> int:
    if not args.yes:
        err("rotate requires --yes to confirm.")
        return 1
    # Before NAUTILUS_REVIEWER: a missing target is the more fundamental error,
    # and reporting the env var first sends the operator down the wrong path.
    if _require_url(args, "rotate") is None:
        return 2
    try:
        reviewer = require_reviewer()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 1

    code, payload = _call(
        args, "rotate", "POST", "/v1/keys/rotate", {"reviewer": reviewer}, transport
    )
    if payload is None:
        return code
    if getattr(args, "json", False):
        print(json.dumps(payload))
    else:
        ok(f"rotated: new primary kid={payload.get('new_primary_kid')}  reviewer={reviewer}")
    return 0


def _cmd_revoke(args: argparse.Namespace, *, transport: httpx.BaseTransport | None = None) -> int:
    if not args.yes:
        err("revoke requires --yes to confirm.")
        return 1
    # Before NAUTILUS_REVIEWER: a missing target is the more fundamental error,
    # and reporting the env var first sends the operator down the wrong path.
    if _require_url(args, "revoke") is None:
        return 2
    try:
        reviewer = require_reviewer()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 1

    code, payload = _call(
        args,
        "revoke",
        "POST",
        f"/v1/keys/{args.kid}/revoke",
        {"reviewer": reviewer, "reason": args.reason},
        transport,
    )
    if payload is None:
        return code
    if getattr(args, "json", False):
        print(json.dumps(payload))
    else:
        ok(f"revoked: kid={args.kid}  reason={args.reason!r}  reviewer={reviewer}")
    return 0


__all__ = ["add_subparser", "dispatch"]
