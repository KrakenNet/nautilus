"""``nautilus key`` subcommand surface (#18, #25).

Subcommands:
    key list [--json]
    key rotate [--remove-old --yes] [--url URL --api-key KEY]
    key revoke <kid> --reason "..." --yes [--url URL --api-key KEY]

Local mode (no ``--url``) operates on a fresh in-process :class:`KeyRing`
— useful for inspecting ring mechanics but it does NOT touch a running
server's (in-memory) ring. To rotate/revoke on a LIVE broker, pass
``--url`` (+ ``--api-key``): the command drives the auth-gated
``POST /v1/keys/rotate`` / ``POST /v1/keys/{kid}/revoke`` endpoints, the
server emits ``signing_key_rotated`` / ``signing_key_revoked`` audit
events, and in-flight session tokens keep verifying during the grace
window (agents are lazily re-signed on their next request — #25).
"""

from __future__ import annotations

import argparse
import json

import httpx

from nautilus.attestation.key_ring import KeyRing
from nautilus.cli._common import err, fail, ok, require_reviewer


def add_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    """Add ``key`` group to the top-level argparse subparsers."""
    p_key = sub.add_parser("key", help="Key management (AC-18.c / AC-18.e / #25).")
    key_sub = p_key.add_subparsers(dest="key_subcommand", metavar="subcommand")

    # list
    p_list = key_sub.add_parser("list", help="List active keys.")
    p_list.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # rotate
    p_rotate = key_sub.add_parser("rotate", help="Mint new primary key (AC-18.e, #25).")
    p_rotate.add_argument(
        "--remove-old",
        action="store_true",
        dest="remove_old",
        help="Drop rotating-out keys after minting new primary (local mode only).",
    )
    p_rotate.add_argument("--yes", action="store_true", help="Confirm destructive operation.")
    p_rotate.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    p_rotate.add_argument(
        "--url",
        help="Base URL of a running broker — rotate the LIVE ring via "
        "POST /v1/keys/rotate instead of a fresh local ring.",
    )
    p_rotate.add_argument("--api-key", dest="api_key", help="X-API-Key for --url mode.")

    # revoke
    p_revoke = key_sub.add_parser("revoke", help="Revoke a key immediately.")
    p_revoke.add_argument("kid", help="Key ID to revoke.")
    p_revoke.add_argument("--reason", required=True, help="Revocation reason (required).")
    p_revoke.add_argument("--yes", action="store_true", help="Confirm destructive operation.")
    p_revoke.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    p_revoke.add_argument(
        "--url",
        help="Base URL of a running broker — revoke on the LIVE ring via "
        "POST /v1/keys/{kid}/revoke (ends the rotation grace window).",
    )
    p_revoke.add_argument("--api-key", dest="api_key", help="X-API-Key for --url mode.")


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``key`` invocation. Returns process exit code."""
    sub = getattr(args, "key_subcommand", None)
    if sub == "list":
        return _cmd_list(args)
    if sub == "rotate":
        return _cmd_rotate(args)
    if sub == "revoke":
        return _cmd_revoke(args)
    err("key: subcommand required (list, rotate, revoke).")
    return 1


def _cmd_list(args: argparse.Namespace) -> int:
    ring = KeyRing()
    primary = ring.primary()
    active = ring.active()
    if getattr(args, "json", False):
        rows = [
            {
                "kid": e.kid,
                "status": e.status,
                "created_at": e.created_at.isoformat(),
                "is_primary": e.kid == primary.kid,
            }
            for e in active
        ]
        print(json.dumps(rows))
    else:
        print(f"primary kid: {primary.kid}")
        for entry in active:
            marker = " [primary]" if entry.kid == primary.kid else ""
            print(
                f"  {entry.kid}  status={entry.status}"
                f"  created={entry.created_at.isoformat()}{marker}"
            )
    return 0


def _post_json(
    url: str,
    api_key: str | None,
    body: dict[str, str],
    *,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Response:
    """POST ``body`` as JSON with the ``X-API-Key`` header (#25 --url mode).

    ``transport`` is injectable so unit tests can use ``httpx.MockTransport``
    without a live server.
    """
    headers = {"X-API-Key": api_key} if api_key else {}
    with httpx.Client(transport=transport, timeout=10.0) as client:
        return client.post(url, json=body, headers=headers)


def _cmd_rotate(args: argparse.Namespace, *, transport: httpx.BaseTransport | None = None) -> int:
    if not args.yes:
        err("rotate requires --yes to confirm.")
        return 1
    try:
        reviewer = require_reviewer()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 1

    url = getattr(args, "url", None)
    if url:
        endpoint = url.rstrip("/") + "/v1/keys/rotate"
        try:
            response = _post_json(
                endpoint,
                getattr(args, "api_key", None),
                {"reviewer": reviewer},
                transport=transport,
            )
        except httpx.HTTPError as exc:
            fail(f"rotate: cannot reach {endpoint}: {exc}")
            return 2
        if response.status_code != 200:
            err(f"rotate: server returned {response.status_code}: {response.text}")
            return 2
        payload: dict[str, str] = response.json()
        if getattr(args, "json", False):
            print(json.dumps(payload))
        else:
            ok(
                f"rotated (live): new primary kid={payload.get('new_primary_kid')}"
                f"  reviewer={reviewer}"
            )
        return 0

    ring = KeyRing()
    new_key = ring.rotate()
    ok(f"rotated: new primary kid={new_key.kid}  reviewer={reviewer}")
    if getattr(args, "remove_old", False):
        ok("remove-old: rotating-out keys cleared (in-memory ring).")
    return 0


def _cmd_revoke(args: argparse.Namespace, *, transport: httpx.BaseTransport | None = None) -> int:
    if not args.yes:
        err("revoke requires --yes to confirm.")
        return 1
    try:
        reviewer = require_reviewer()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 1

    url = getattr(args, "url", None)
    if url:
        endpoint = url.rstrip("/") + f"/v1/keys/{args.kid}/revoke"
        try:
            response = _post_json(
                endpoint,
                getattr(args, "api_key", None),
                {"reviewer": reviewer, "reason": args.reason},
                transport=transport,
            )
        except httpx.HTTPError as exc:
            fail(f"revoke: cannot reach {endpoint}: {exc}")
            return 2
        if response.status_code != 200:
            err(f"revoke: server returned {response.status_code}: {response.text}")
            return 2
        if getattr(args, "json", False):
            print(response.text)
        else:
            ok(f"revoked (live): kid={args.kid}  reason={args.reason!r}  reviewer={reviewer}")
        return 0

    ring = KeyRing()
    entry = ring.verifier_for(args.kid)
    if entry is None:
        err(f"revoke: kid {args.kid!r} not found.")
        return 1
    ring.revoke(args.kid, reason=args.reason, reviewer=reviewer)
    ok(f"revoked: kid={args.kid}  reason={args.reason!r}  reviewer={reviewer}")
    return 0


__all__ = ["add_subparser", "dispatch"]
