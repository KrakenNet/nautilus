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
        help="Filter by status (active, quarantined, unknown).",
    )
    p_list.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # schema
    p_schema = adapters_sub.add_parser("schema", help="Print AdapterSchema for an adapter.")
    p_schema.add_argument("name", help="Adapter name/id.")
    p_schema.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # schema-fingerprint
    p_fp = adapters_sub.add_parser(
        "schema-fingerprint", help="Print current fingerprint hash for an adapter."
    )
    p_fp.add_argument("name", help="Adapter name/id.")

    # schema-diff
    p_diff = adapters_sub.add_parser("schema-diff", help="Show drift vs stored fingerprint.")
    p_diff.add_argument("name", help="Adapter name/id.")
    p_diff.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # schema-ack
    p_ack = adapters_sub.add_parser(
        "schema-ack", help="Acknowledge drift; update stored fingerprint (AC-21.g)."
    )
    p_ack.add_argument("name", help="Adapter name/id.")
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
    """List registered adapters from the broker config (best-effort)."""
    from nautilus.adapters.base import Adapter

    adapters: list[Adapter]
    try:
        from nautilus.core.broker import Broker

        broker = Broker.from_config(None)  # type: ignore[arg-type]
        adapters = list(broker._adapters.values())  # pyright: ignore[reportPrivateUsage]
    except Exception:  # noqa: BLE001
        adapters = []

    status_filter = getattr(args, "status", None)
    if status_filter:
        adapters = [a for a in adapters if getattr(a, "status", "unknown") == status_filter]

    if getattr(args, "json", False):
        out: list[dict[str, object]] = []
        for a in adapters:
            out.append(
                {
                    "id": getattr(a, "adapter_id", str(a)),
                    "status": getattr(a, "status", "unknown"),
                }
            )
        print(json.dumps(out))
        return 0

    if not adapters:
        ok("no adapters registered")
        return 0

    for a in adapters:
        aid = getattr(a, "adapter_id", str(a))
        status = getattr(a, "status", "unknown")
        print(f"  {aid}  status={status}")
    return 0


def _cmd_schema(args: argparse.Namespace) -> int:

    schema = _get_adapter_schema(args.name)
    if schema is None:
        warn(f"no schema available for adapter {args.name!r}")
        if getattr(args, "json", False):
            print(json.dumps(None))
        return 0

    if getattr(args, "json", False):
        print(json.dumps(_schema_as_dict(schema), default=str))
        return 0

    d = _schema_as_dict(schema)
    for k, v in d.items():
        print(f"  {k}: {v}")
    return 0


def _cmd_schema_fingerprint(args: argparse.Namespace) -> int:
    schema = _get_adapter_schema(args.name)
    if schema is None:
        warn(f"no schema available for adapter {args.name!r}")
        return 0

    fp = schema.fingerprint()  # type: ignore[attr-defined]
    print(fp)
    return 0


def _cmd_schema_diff(args: argparse.Namespace) -> int:
    from nautilus.adapters.schema import SchemaFingerprintStore

    store = SchemaFingerprintStore(root=None)
    stored_fp = store.get(args.name)
    current_schema = _get_adapter_schema(args.name)

    if current_schema is None:
        warn(f"no schema available for adapter {args.name!r}")
        return 0

    current_fp = current_schema.fingerprint()  # type: ignore[attr-defined]

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

    from nautilus.adapters.schema import SchemaFingerprintStore

    store = SchemaFingerprintStore(root=None)
    current_schema = _get_adapter_schema(args.name)

    if current_schema is None:
        err(f"no schema available for adapter {args.name!r}; cannot ack")
        return 1

    current_fp = current_schema.fingerprint()  # type: ignore[attr-defined]
    store.record_ack(
        args.name,
        current_fp,
        reviewer=reviewer,
        reason=args.reason,
    )
    ok(f"schema-ack recorded for {args.name!r} by {reviewer}: {args.reason}")
    return 0


def _get_adapter_schema(name: str) -> AdapterSchema | None:
    """Try to retrieve an AdapterSchema for the named adapter. Best-effort."""
    from nautilus.adapters.schema import AdapterSchema

    # Return an unknown-type schema as a best-effort stub when no live adapter.
    return AdapterSchema.unknown(adapter_id=name, source_type="unknown")


__all__ = ["add_subparser", "dispatch"]
