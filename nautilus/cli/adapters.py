"""``nautilus adapters`` subcommand surface (#21 + #17).

Subcommands:
    adapters new <name> [--dir PATH]
    adapters list [--status active|quarantined|unknown] [--json]
    adapters schema <name> [--json]
    adapters schema-fingerprint <name>
    adapters schema-diff <name> [--json]
    adapters schema-ack <name> --reason TEXT --yes
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nautilus.cli._common import err, ok, require_reviewer, warn

if TYPE_CHECKING:
    from nautilus.adapters.schema import AdapterSchema

# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def add_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    """Add ``adapters`` group to the top-level argparse subparsers."""
    p = sub.add_parser("adapters", help="Adapter registry and schema operations.")
    adapters_sub = p.add_subparsers(dest="adapters_subcommand", metavar="subcommand")

    # new
    p_new = adapters_sub.add_parser(
        "new", help="Scaffold a new adapter package from the bundled template."
    )
    p_new.add_argument("name", help="Distribution name, e.g. my-csv-adapter.")
    p_new.add_argument(
        "--dir",
        default=".",
        dest="dir",
        help="Parent directory to create the package in (default: current directory).",
    )

    # list
    p_list = adapters_sub.add_parser("list", help="List registered adapters.")
    p_list.add_argument(
        "--status",
        default=None,
        help="Filter by status (active, quarantined). Requires --url: quarantine "
        "lives in the serving process, not in the config.",
    )
    p_list.add_argument(
        "--config",
        default=None,
        help="Path to nautilus.yaml (default: ./nautilus.yaml when present).",
    )
    p_list.add_argument("--url", default=None, help="Base URL of a running server.")
    p_list.add_argument("--api-key", dest="api_key", help="X-API-Key for --url mode.")
    p_list.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # schema
    p_schema = adapters_sub.add_parser("schema", help="Print AdapterSchema for an adapter.")
    p_schema.add_argument("name", help="Adapter name/id.")
    p_schema.add_argument(
        "--config",
        default=None,
        help="Path to nautilus.yaml (default: ./nautilus.yaml when present).",
    )
    p_schema.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # schema-fingerprint
    p_fp = adapters_sub.add_parser(
        "schema-fingerprint", help="Print current fingerprint hash for an adapter."
    )
    p_fp.add_argument("name", help="Adapter name/id.")
    p_fp.add_argument(
        "--config",
        default=None,
        help="Path to nautilus.yaml (default: ./nautilus.yaml when present).",
    )

    # schema-diff
    p_diff = adapters_sub.add_parser("schema-diff", help="Show drift vs stored fingerprint.")
    p_diff.add_argument("name", help="Adapter name/id.")
    p_diff.add_argument("--config", required=True, help="Path to nautilus.yaml.")
    p_diff.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # schema-ack
    p_ack = adapters_sub.add_parser(
        "schema-ack", help="Acknowledge drift; update stored fingerprint (AC-21.g)."
    )
    p_ack.add_argument("name", help="Adapter name/id.")
    p_ack.add_argument("--config", required=True, help="Path to nautilus.yaml.")
    p_ack.add_argument("--reason", required=True, help="Reason for acknowledgement.")
    p_ack.add_argument(
        "--yes",
        action="store_true",
        help="Confirm acknowledgement (required).",
    )


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``adapters`` invocation. Returns process exit code."""
    try:
        subcommand = getattr(args, "adapters_subcommand", None)
        if subcommand == "new":
            return _cmd_new(args)
        if subcommand == "list":
            return _cmd_list(args)
        if subcommand == "schema":
            return _cmd_schema(args)
        if subcommand == "schema-fingerprint":
            return _cmd_schema_fingerprint(args)
        if subcommand == "schema-diff":
            return _cmd_schema_diff(args)
        if subcommand == "schema-ack":
            return _cmd_schema_ack(args)
        err(
            "adapters: no subcommand given"
            " (try: new, list, schema, schema-fingerprint, schema-diff, schema-ack)"
        )
        return 2
    except SystemExit as exc:
        # require_reviewer() calls sys.exit(1); surface as return code.
        return int(exc.code) if exc.code is not None else 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _open_store() -> object:  # pyright: ignore[reportUnusedFunction]
    from nautilus.adapters.schema import SchemaFingerprintStore

    return SchemaFingerprintStore(root=None)


def _resolve_config(args: argparse.Namespace) -> str | None:
    """Config path from ``--config``, else ``./nautilus.yaml`` when it exists.

    These commands took no config at all and rebuilt a broker from ``None``
    inside a bare ``except``, so every invocation reported an empty registry
    with exit 0 -- including the one the Grafana how-to lists under "what to
    alert on".
    """
    explicit: str | None = getattr(args, "config", None)
    if explicit:
        return explicit
    default = Path("nautilus.yaml")
    return str(default) if default.is_file() else None


def _live_adapter_schema(config_path: str, name: str) -> tuple[Any, AdapterSchema | None]:
    """Return ``(broker, schema)`` for the configured adapter ``name``.

    Baseline operations have to run against the broker's own fingerprint
    store and the adapter's real schema. Comparing — or acknowledging — the
    ``AdapterSchema.unknown`` stub would write a baseline the broker can
    never match, quarantining the adapter permanently.

    ``schema`` is ``None`` when the adapter is unknown, cannot connect, or
    does not introspect its schema.
    """
    import asyncio

    from nautilus.core.broker import Broker

    broker = Broker.from_config(config_path)
    adapter = broker._adapters.get(name)  # pyright: ignore[reportPrivateUsage]
    if adapter is None or not hasattr(adapter, "get_schema"):
        asyncio.run(broker.aclose())
        return broker, None

    async def _fetch() -> AdapterSchema | None:
        try:
            await adapter.connect(
                broker._registry.get(name)  # pyright: ignore[reportPrivateUsage]
            )
            return await adapter.get_schema()  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001 — reported, not raised
            warn(f"could not read schema for {name!r}: {exc}")
            return None
        finally:
            await broker.aclose()

    return broker, asyncio.run(_fetch())


def _schema_as_dict(schema: AdapterSchema) -> dict[str, Any]:
    d = dataclasses.asdict(schema)
    d["fetched_at"] = schema.fetched_at.isoformat()
    return d


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

_NAME_PATTERN = r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$"

# Template shipped as package data — see [tool.setuptools.package-data].
_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates" / "adapter"


def _scaffold_names(name: str) -> dict[str, str]:
    """Derive template variables from the distribution name.

    ``my-csv-adapter`` -> package ``my_csv_adapter``, class ``MyCsvAdapter``,
    source type ``my-csv`` (a trailing ``-adapter`` token is dropped from the
    class name and source type, not the package name).
    """
    parts = name.split("-")
    stem_parts = parts[:-1] if len(parts) > 1 and parts[-1] == "adapter" else parts
    return {
        "adapter_name": name,
        "package_name": name.replace("-", "_"),
        "class_name": "".join(p.capitalize() for p in stem_parts) + "Adapter",
        "source_type": "-".join(stem_parts),
    }


def _cmd_new(args: argparse.Namespace) -> int:
    """Scaffold an adapter package via the bundled copier template (#17)."""
    import re

    name: str = args.name
    if not re.match(_NAME_PATTERN, name):
        err(f"invalid adapter name {name!r} (expected lowercase-dashed, e.g. my-csv-adapter)")
        return 1

    dest = Path(args.dir) / name
    if dest.exists() and any(dest.iterdir()):
        err(f"destination already exists and is not empty: {dest}")
        return 1

    try:
        from copier import run_copy
    except ImportError:
        err("copier is required for 'adapters new' — install it with: pip install copier")
        return 1

    data = _scaffold_names(name)
    run_copy(
        str(_TEMPLATE_DIR),
        str(dest),
        data=data,
        defaults=True,
        quiet=True,
    )

    ok(f"scaffolded adapter package at {dest}")
    print(f"  source type : {data['source_type']}")
    print(f"  class       : {data['package_name']}.{data['class_name']}")
    print("  next steps  :")
    print(f"    cd {dest}")
    print('    pip install -e ".[test]" && pytest -v')
    print("    nautilus adapters list   # confirm discovery once installed")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    """List adapters from a running server (--url) or from a config file."""
    url: str | None = getattr(args, "url", None)
    status_filter: str | None = getattr(args, "status", None)

    if url:
        rows = _remote_adapters(url, getattr(args, "api_key", None))
        if rows is None:
            return 1
    else:
        if status_filter:
            err(
                f"--status {status_filter!r} needs --url: quarantine state lives in "
                "the serving process, so a config file cannot answer it. Reporting "
                "an empty list here would look like 'nothing is quarantined'."
            )
            return 1
        config_path = _resolve_config(args)
        if config_path is None:
            err(
                "no config found: pass --config PATH, or run from a directory "
                "containing nautilus.yaml"
            )
            return 1
        rows = _configured_adapters(config_path)
        if rows is None:
            return 1

    if status_filter:
        rows = [r for r in rows if r["status"] == status_filter]

    if getattr(args, "json", False):
        print(json.dumps(rows))
        return 0

    if not rows:
        ok("no adapters registered")
        return 0

    for row in rows:
        print(f"  {row['id']}  type={row['type']}  status={row['status']}")
    return 0


def _configured_adapters(config_path: str) -> list[dict[str, str]] | None:
    """Adapters declared by ``config_path``; ``None`` after reporting an error.

    ``status`` is ``configured``, not ``active``: this process is not the one
    serving requests, so it cannot know whether an adapter is connected or
    quarantined. Saying ``active`` here would be a guess dressed as a fact.
    """
    import asyncio

    from nautilus.core.broker import Broker

    try:
        broker = Broker.from_config(config_path)
    except Exception as exc:  # noqa: BLE001 — a bad config is the operator's answer
        err(f"could not load {config_path}: {exc}")
        return None
    try:
        return [
            {"id": source.id, "type": source.type, "status": "configured"}
            for source in broker.sources
        ]
    finally:
        asyncio.run(broker.aclose())


def _remote_adapters(url: str, api_key: str | None) -> list[dict[str, str]] | None:
    """Adapters and live status from a running server."""
    import httpx

    headers = {"X-API-Key": api_key} if api_key else {}
    try:
        response = httpx.get(f"{url.rstrip('/')}/v1/adapters", headers=headers, timeout=10)
        response.raise_for_status()
    except Exception as exc:  # noqa: BLE001 — surfaced to the operator
        err(f"could not reach {url}: {exc}")
        return None
    payload: Any = response.json()
    return list(payload.get("adapters", []))


def _cmd_schema(args: argparse.Namespace) -> int:
    schema = _get_adapter_schema(args)
    if schema is None:
        err(f"no schema available for adapter {args.name!r}")
        if getattr(args, "json", False):
            print(json.dumps(None))
        return 1

    if getattr(args, "json", False):
        print(json.dumps(_schema_as_dict(schema), default=str))
        return 0

    d = _schema_as_dict(schema)
    for k, v in d.items():
        print(f"  {k}: {v}")
    return 0


def _cmd_schema_fingerprint(args: argparse.Namespace) -> int:
    schema = _get_adapter_schema(args)
    if schema is None:
        err(f"no schema available for adapter {args.name!r}")
        return 1

    fp = schema.fingerprint()  # type: ignore[attr-defined]
    print(fp)
    return 0


def _cmd_schema_diff(args: argparse.Namespace) -> int:
    broker, current_schema = _live_adapter_schema(args.config, args.name)
    stored_fp = broker.fingerprint_store.get(args.name)

    if current_schema is None:
        warn(f"no schema available for adapter {args.name!r}")
        return 0

    current_fp = current_schema.fingerprint()

    if stored_fp is None:
        warn(f"no stored fingerprint for {args.name!r}; treating as new")
        if getattr(args, "json", False):
            print(json.dumps({"status": "no_baseline", "current": current_fp}))
        else:
            print(f"  no baseline fingerprint for {args.name!r}")
            print(f"  current: {current_fp}")
        return 0

    if stored_fp == current_fp:
        if getattr(args, "json", False):
            print(json.dumps({"status": "clean", "fingerprint": current_fp}))
        else:
            ok(f"no drift for {args.name!r} (fingerprint matches)")
        return 0

    # Fingerprints differ — show diff entries if we can compute them

    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "status": "drift",
                    "stored": stored_fp,
                    "current": current_fp,
                }
            )
        )
    else:
        print(f"  adapter : {args.name}")
        print(f"  stored  : {stored_fp}")
        print(f"  current : {current_fp}")
        print("  DRIFT DETECTED")
    return 0


def _cmd_schema_ack(args: argparse.Namespace) -> int:
    if not getattr(args, "yes", False):
        err("schema-ack requires --yes to confirm")
        return 1

    reviewer = require_reviewer()  # exits 1 if NAUTILUS_REVIEWER not set

    broker, current_schema = _live_adapter_schema(args.config, args.name)

    if current_schema is None:
        err(f"no schema available for adapter {args.name!r}; cannot ack")
        return 1

    current_fp = current_schema.fingerprint()
    broker.fingerprint_store.record_ack(
        args.name,
        current_fp,
        reviewer=reviewer,
        reason=args.reason,
    )
    # The ack overrides a fail-closed decision the broker already audited, so
    # it belongs in the same log next to the drift entry it answers.
    broker.emit_adapter_event("schema_drift_severity_overridden", args.name)
    ok(f"schema-ack recorded for {args.name!r} by {reviewer}: {args.reason}")
    return 0


def _get_adapter_schema(args: argparse.Namespace) -> AdapterSchema | None:
    """Read the named adapter's real schema, or ``None``.

    This used to return ``AdapterSchema.unknown(name, "unknown")``
    unconditionally, without consulting a config, a registry or an adapter:
    a nonexistent adapter was confirmed as real with exit 0, and a real one
    printed a digest matching neither its live schema nor its stored
    baseline. The ``if schema is None`` branch in both callers was written
    for this and never reached.
    """
    config_path = _resolve_config(args)
    if config_path is None:
        err("no config found: pass --config PATH, or run from a directory containing nautilus.yaml")
        return None
    _, schema = _live_adapter_schema(config_path, args.name)
    return schema


__all__ = ["add_subparser", "dispatch"]
