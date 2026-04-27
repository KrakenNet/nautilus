"""Nautilus CLI — serve / health / version / sources / cost-caps subcommands (FR-30, D-15).

Stdlib :mod:`argparse` only — no click/typer per D-15. The ``health``
probe uses :func:`urllib.request.urlopen` (no ``requests`` dependency) so
the CLI stays usable in minimal / air-gapped images (NFR-1, NFR-10).

Design references:
    * §3.15 — CLI surface + ``--air-gapped`` enforcement (AC-15.3).
    * NFR-14 — single :class:`Broker` singleton shared across transports
      when ``--transport both`` is selected.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import sys
import tempfile
import urllib.error
import urllib.request
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import yaml

from nautilus.core.broker import _merge_cost_caps  # pyright: ignore[reportPrivateUsage]

if TYPE_CHECKING:
    from nautilus.config.models import CostCapConfig
    from nautilus.core.broker import Broker

_DEFAULT_HEALTH_URL = "http://localhost:8000/readyz"
_DEFAULT_BIND = "127.0.0.1:8000"
_HEALTH_TIMEOUT_S = 5


def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argparse parser with three subcommands."""
    parser = argparse.ArgumentParser(
        prog="nautilus",
        description=(
            "Nautilus reasoning-engine CLI (serve / health / version / sources / cost-caps)."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    # version ---------------------------------------------------------
    sub.add_parser("version", help="Print the installed nautilus package version.")

    # health ----------------------------------------------------------
    p_health = sub.add_parser(
        "health",
        help="Probe a nautilus /readyz endpoint over HTTP (exit 0 on 200).",
    )
    p_health.add_argument(
        "--url",
        default=_DEFAULT_HEALTH_URL,
        help=f"Readiness URL (default: {_DEFAULT_HEALTH_URL}).",
    )

    # serve -----------------------------------------------------------
    p_serve = sub.add_parser(
        "serve",
        help="Run the nautilus transport(s): REST, MCP, or both.",
    )
    p_serve.add_argument(
        "--config",
        required=True,
        help="Path to nautilus.yaml.",
    )
    p_serve.add_argument(
        "--transport",
        choices=("rest", "mcp", "both"),
        default="rest",
        help="Transport surface to expose (default: rest).",
    )
    p_serve.add_argument(
        "--mcp-mode",
        choices=("stdio", "http"),
        default="stdio",
        help="MCP transport mode when --transport is mcp or both (default: stdio).",
    )
    p_serve.add_argument(
        "--bind",
        default=_DEFAULT_BIND,
        help=f"HOST:PORT for REST (and MCP http) bind (default: {_DEFAULT_BIND}).",
    )
    p_serve.add_argument(
        "--air-gapped",
        action="store_true",
        help=(
            "Force analysis.mode='pattern' and refuse any LLM provider "
            "config (NFR-1). WARN is emitted naming each overridden field."
        ),
    )

    # sources ---------------------------------------------------------
    p_sources = sub.add_parser(
        "sources",
        help=(
            "Manage per-source enable/disable state (US-3). "
            "Operates in-process against the configured SourceStateStore."
        ),
    )
    sources_sub = p_sources.add_subparsers(
        dest="sources_op",
        required=True,
        metavar="operation",
    )

    # sources list
    p_sources_list = sources_sub.add_parser(
        "list",
        help="List all persisted source-state rows as a plain-text table.",
    )
    p_sources_list.add_argument(
        "--config",
        required=True,
        help="Path to nautilus.yaml.",
    )

    # sources disable
    p_sources_disable = sources_sub.add_parser(
        "disable",
        help="Disable a source with an operator-supplied reason.",
    )
    p_sources_disable.add_argument("source_id", help="Source identifier (registry key).")
    p_sources_disable.add_argument(
        "--reason",
        required=True,
        help="Operator-supplied reason string (AC-3.6).",
    )
    p_sources_disable.add_argument(
        "--actor",
        default=None,
        help="Principal recording the change (defaults to $USER or 'cli').",
    )
    p_sources_disable.add_argument(
        "--config",
        required=True,
        help="Path to nautilus.yaml.",
    )

    # sources enable
    p_sources_enable = sources_sub.add_parser(
        "enable",
        help="Re-enable a previously disabled source.",
    )
    p_sources_enable.add_argument("source_id", help="Source identifier (registry key).")
    p_sources_enable.add_argument(
        "--actor",
        default=None,
        help="Principal recording the change (defaults to $USER or 'cli').",
    )
    p_sources_enable.add_argument(
        "--config",
        required=True,
        help="Path to nautilus.yaml.",
    )

    # sources schema-ack
    p_sources_schema_ack = sources_sub.add_parser(
        "schema-ack",
        help=(
            "Record operator acknowledgement of a publisher schema hash "
            "so a paused source resumes ingest (US-4, AC-4.10)."
        ),
    )
    p_sources_schema_ack.add_argument("source_id", help="Source identifier (registry key).")
    p_sources_schema_ack.add_argument(
        "--new-hash",
        dest="new_hash",
        required=True,
        help="Current published schema hash the operator is acknowledging.",
    )
    p_sources_schema_ack.add_argument(
        "--actor",
        default=None,
        help="Principal recording the ack (defaults to $USER or 'cli').",
    )
    p_sources_schema_ack.add_argument(
        "--config",
        required=True,
        help="Path to nautilus.yaml.",
    )

    # cost-caps ------------------------------------------------------
    p_cost_caps = sub.add_parser(
        "cost-caps",
        help=(
            "Inspect effective per-request cost caps (US-2, FR-18/19). "
            "Loads the config in-process and merges global + per-source overrides."
        ),
    )
    cost_caps_sub = p_cost_caps.add_subparsers(
        dest="cost_caps_op",
        required=True,
        metavar="operation",
    )

    # cost-caps show
    p_cost_caps_show = cost_caps_sub.add_parser(
        "show",
        help="Render the effective merged caps per source as a plain-text table.",
    )
    p_cost_caps_show.add_argument(
        "--source",
        default=None,
        help="Optional single source-id filter (exact match; no glob, no multi-select).",
    )
    p_cost_caps_show.add_argument(
        "--config",
        required=True,
        help="Path to nautilus.yaml.",
    )

    return parser


# ----------------------------------------------------------------------
# version
# ----------------------------------------------------------------------


def _cmd_version() -> int:
    try:
        ver = metadata.version("nautilus")
    except metadata.PackageNotFoundError:
        print("nautilus (version unknown — package metadata missing)", file=sys.stderr)
        return 1
    print(ver)
    return 0


# ----------------------------------------------------------------------
# health
# ----------------------------------------------------------------------


def _cmd_health(url: str) -> int:
    """Issue a GET against ``url`` with a 5s timeout. Exit 0 on HTTP 200."""
    try:
        with urllib.request.urlopen(url, timeout=_HEALTH_TIMEOUT_S) as resp:  # noqa: S310 - operator-controlled URL
            status = int(resp.status)
            if status == 200:
                print(f"OK {status} {url}")
                return 0
            print(f"FAIL {status} {url}", file=sys.stderr)
            return 1
    except urllib.error.HTTPError as exc:
        print(f"FAIL {exc.code} {url}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"FAIL unreachable {url}: {exc}", file=sys.stderr)
        return 1


# ----------------------------------------------------------------------
# serve
# ----------------------------------------------------------------------


def _split_bind(bind: str) -> tuple[str, int]:
    """Split ``HOST:PORT`` on the first ``:``; reject malformed values."""
    if ":" not in bind:
        raise ValueError(f"--bind must be HOST:PORT, got {bind!r}")
    host, _, port_s = bind.partition(":")
    if not host or not port_s:
        raise ValueError(f"--bind must be HOST:PORT, got {bind!r}")
    try:
        port = int(port_s)
    except ValueError as exc:
        raise ValueError(f"--bind port must be an integer, got {port_s!r}") from exc
    return host, port


def _enforce_air_gap(raw: dict[str, Any]) -> dict[str, Any]:
    """Mutate ``raw`` YAML dict for ``--air-gapped``; emit WARN on each override.

    Overrides ``analysis.mode`` to ``"pattern"`` and drops
    ``analysis.provider`` (NFR-1, AC-15.3). Non-destructive on configs
    that already conform (no WARN emitted in that case).
    """
    analysis_raw = raw.get("analysis")
    analysis: dict[str, Any] = (
        cast("dict[str, Any]", analysis_raw) if isinstance(analysis_raw, dict) else {}
    )
    raw["analysis"] = analysis

    current_mode: Any = analysis.get("mode", "pattern")
    if current_mode != "pattern":
        print(
            f"WARN: --air-gapped overrides analysis.mode from "
            f"{current_mode!r} to 'pattern' (NFR-1)",
            file=sys.stderr,
        )
        analysis["mode"] = "pattern"

    prov: Any = analysis.get("provider")
    if prov is not None:
        provider_type = "<unknown>"
        if isinstance(prov, dict):
            prov_typed = cast("dict[str, Any]", prov)
            provider_type = str(prov_typed.get("type", "<unknown>"))
        print(
            f"WARN: --air-gapped refuses analysis.provider "
            f"(type={provider_type!r}); dropping it (NFR-1)",
            file=sys.stderr,
        )
        analysis["provider"] = None

    return raw


def _load_config_for_serve(config_path: Path, *, air_gapped: bool) -> Path:
    """Return a config path ready for :meth:`Broker.from_config`.

    When ``air_gapped`` is set and the raw YAML carries a non-pattern mode
    or a provider stanza, the file is rewritten into a temp path with
    those fields neutralized. Otherwise the original ``config_path`` is
    returned unchanged.
    """
    if not air_gapped:
        return config_path

    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Unable to read config '{config_path}': {exc}") from exc

    loaded: Any = yaml.safe_load(raw_text)
    if not isinstance(loaded, dict):
        # Let Broker.from_config surface the normal validation error.
        return config_path

    raw: dict[str, Any] = cast("dict[str, Any]", loaded)
    before = yaml.safe_dump(raw, sort_keys=True)
    raw = _enforce_air_gap(raw)
    after = yaml.safe_dump(raw, sort_keys=True)
    if before == after:
        return config_path

    tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115 - kept open across call site
        mode="w",
        suffix=".yaml",
        prefix="nautilus-airgap-",
        delete=False,
        encoding="utf-8",
    )
    try:
        tmp.write(after)
    finally:
        tmp.close()
    return Path(tmp.name)


async def _run_rest(broker: Broker, host: str, port: int) -> None:
    """Run uvicorn against :func:`create_app` with an injected broker."""
    import uvicorn

    from nautilus.transport.fastapi_app import create_app

    app = create_app(None, existing_broker=broker)
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


async def _run_mcp(broker: Broker, mode: str, host: str, port: int) -> None:
    """Run FastMCP with the given transport mode and the injected broker."""
    from nautilus.transport.mcp_server import create_server

    mcp = create_server(None, existing_broker=broker)
    # The injected-broker contract (mcp_server docstring) leaves setup()
    # to the caller — idempotent so safe in the --transport both path.
    await broker.setup()

    if mode == "stdio":
        await mcp.run_stdio_async()
    else:
        # The FastMCP settings object carries host/port for streamable-http.
        mcp.settings.host = host
        mcp.settings.port = port
        await mcp.run_streamable_http_async()


async def _run_both(
    broker: Broker,
    host: str,
    port: int,
    mcp_mode: str,
) -> None:
    """Run REST + MCP concurrently on the same asyncio loop (NFR-14).

    The shared ``broker`` singleton satisfies NFR-14 — a single Fathom
    engine and adapter pool backs both transports. MCP http is bound to
    ``port + 1`` so the two servers don't collide on the same socket.
    """
    mcp_port = port + 1 if mcp_mode == "http" else port
    await asyncio.gather(
        _run_rest(broker, host, port),
        _run_mcp(broker, mcp_mode, host, mcp_port),
    )


def _cmd_serve(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    if not config_path.is_file():
        print(
            f"ERROR: config path does not exist or is not a file: {config_path}",
            file=sys.stderr,
        )
        return 2

    try:
        host, port = _split_bind(args.bind)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        effective_path = _load_config_for_serve(
            config_path,
            air_gapped=bool(args.air_gapped),
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # Broker.from_config surfaces ConfigError / validation errors with
    # readable messages; propagate as a non-zero exit before any bind.
    from nautilus.config.loader import ConfigError
    from nautilus.core.broker import Broker

    try:
        broker = Broker.from_config(effective_path)
    except ConfigError as exc:
        print(f"ERROR: invalid config: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - surface wiring failures cleanly
        print(f"ERROR: broker construction failed: {exc}", file=sys.stderr)
        return 2

    transport = args.transport
    mcp_mode = args.mcp_mode

    try:
        if transport == "rest":
            asyncio.run(_run_rest(broker, host, port))
        elif transport == "mcp":
            asyncio.run(_run_mcp(broker, mcp_mode, host, port))
        else:
            asyncio.run(_run_both(broker, host, port, mcp_mode))
    except KeyboardInterrupt:
        pass
    finally:
        # For --transport rest the FastAPI lifespan already closed the
        # broker; aclose() is idempotent so the extra call is safe. A
        # stale/already-closed event loop surfaces as RuntimeError — we
        # silence it since the broker state is what matters here.
        with contextlib.suppress(RuntimeError):
            asyncio.run(broker.aclose())
    return 0


# ----------------------------------------------------------------------
# sources
# ----------------------------------------------------------------------


def _default_actor() -> str:
    """Return a best-effort principal identifier for CLI-initiated changes."""
    return os.environ.get("USER") or "cli"


def _fmt_changed_at(value: Any) -> str:
    """Render ``changed_at`` for the ``list`` table; ``None`` → ``"-"``."""
    if value is None:
        return "-"
    # datetime objects stringify to a stable ISO-ish form; anything else is
    # handed to ``str()`` so unknown backends don't blow up the table render.
    return str(value)


def _render_sources_table(rows: dict[str, Any]) -> str:
    """Render ``load_all()`` output as a fixed-width plain-text table.

    Columns: ``source_id | enabled | reason | actor | changed_at``. Plain
    stdlib printing (no ``rich``) keeps the CLI dependency surface tight
    (D-15). ``reason=None`` renders as ``"-"``.
    """
    header = f"{'source_id':<24} {'enabled':<8} {'reason':<30} {'actor':<16} {'changed_at'}"
    lines: list[str] = [header, "-" * len(header)]
    for source_id in sorted(rows):
        state = rows[source_id]
        enabled = "true" if bool(state.enabled) else "false"
        reason = state.reason if state.reason is not None else "-"
        actor = state.actor
        changed_at = _fmt_changed_at(state.changed_at)
        lines.append(f"{source_id:<24} {enabled:<8} {reason:<30} {actor:<16} {changed_at}")
    return "\n".join(lines)


async def _run_sources_list(broker: Broker) -> int:
    """Print the sources table. Returns process exit code."""
    store = getattr(broker, "_source_state_store", None)
    if store is None:
        print(
            "ERROR: no SourceStateStore is configured (session_store must be "
            "postgres; see design §Component Responsibilities).",
            file=sys.stderr,
        )
        return 2
    rows = await store.load_all()
    print(_render_sources_table(rows))
    return 0


async def _run_sources_set(
    broker: Broker,
    *,
    source_id: str,
    enabled: bool,
    reason: str | None,
    actor: str,
) -> int:
    """Upsert a single row via ``SourceStateStore.set_enabled``."""
    store = getattr(broker, "_source_state_store", None)
    if store is None:
        print(
            "ERROR: no SourceStateStore is configured (session_store must be "
            "postgres; see design §Component Responsibilities).",
            file=sys.stderr,
        )
        return 2
    await store.set_enabled(
        source_id=source_id,
        enabled=enabled,
        reason=reason,
        actor=actor,
    )
    verb = "enabled" if enabled else "disabled"
    print(f"{verb} source {source_id!r} (actor={actor!r})")
    return 0


async def _run_sources_schema_ack(
    broker: Broker,
    *,
    source_id: str,
    new_hash: str,
    actor: str,
) -> int:
    """Upsert a ``nautilus_schema_ack`` row via a freshly-built store.

    The broker itself does not expose a ``SchemaAckStore`` attribute
    (per-adapter :class:`IngestValidator` owns it at ingest-time), so we
    construct a self-contained store against ``session_store.dsn`` —
    same DSN used by :class:`~nautilus.core.source_state_store.SourceStateStore`
    — run ``setup()`` to ensure the table exists, call ``set_ack``, and
    ``aclose()`` in ``finally`` (AC-4.10 resume flow).
    """
    config = broker._config  # pyright: ignore[reportPrivateUsage]
    sess_cfg = config.session_store
    if sess_cfg.backend != "postgres":
        print(
            "ERROR: sources schema-ack requires session_store.backend=postgres "
            "(see design §Component Responsibilities).",
            file=sys.stderr,
        )
        return 2
    dsn = sess_cfg.dsn or os.environ.get("TEST_PG_DSN")
    if not dsn:
        print(
            "ERROR: sources schema-ack requires session_store.dsn (or TEST_PG_DSN).",
            file=sys.stderr,
        )
        return 2

    known_ids = {s.id for s in broker.sources}
    if source_id not in known_ids:
        print(
            f"ERROR: unknown source id: {source_id!r}",
            file=sys.stderr,
        )
        return 2

    from nautilus.ingest.schema_change import SchemaAckStore

    store = SchemaAckStore(dsn, on_failure=sess_cfg.on_failure)
    try:
        await store.setup()
        ack = await store.set_ack(source_id, acked_hash=new_hash, actor=actor)
    finally:
        with contextlib.suppress(Exception):
            await store.aclose()

    hash_prefix = ack.acked_hash[:12]
    print(
        f"Schema acknowledgement recorded: source={ack.source_id} "
        f"hash={hash_prefix}... actor={ack.actor} "
        f"acked_at={ack.acked_at.isoformat()}",
    )
    return 0


async def _run_sources(args: argparse.Namespace) -> int:
    """Async driver for the ``sources`` subcommand group.

    Builds a :class:`Broker` from ``--config``, runs the requested
    operation, and always awaits :meth:`Broker.aclose` so pooled PG
    handles release cleanly (NFR-DEGRAD).
    """
    from nautilus.core.broker import Broker

    broker = Broker.from_config(Path(args.config))
    try:
        await broker.setup()
        op = args.sources_op
        if op == "list":
            return await _run_sources_list(broker)
        if op == "disable":
            actor = args.actor or _default_actor()
            return await _run_sources_set(
                broker,
                source_id=args.source_id,
                enabled=False,
                reason=args.reason,
                actor=actor,
            )
        if op == "enable":
            actor = args.actor or _default_actor()
            return await _run_sources_set(
                broker,
                source_id=args.source_id,
                enabled=True,
                reason=None,
                actor=actor,
            )
        if op == "schema-ack":
            actor = args.actor or _default_actor()
            return await _run_sources_schema_ack(
                broker,
                source_id=args.source_id,
                new_hash=args.new_hash,
                actor=actor,
            )
        # argparse enforces required=True; defensive.
        print(f"ERROR: unknown sources operation: {op!r}", file=sys.stderr)
        return 2
    finally:
        with contextlib.suppress(Exception):
            await broker.aclose()


def _cmd_sources(args: argparse.Namespace) -> int:
    """Sync entrypoint for the ``sources`` subcommand group."""
    config_path = Path(args.config)
    if not config_path.is_file():
        print(
            f"ERROR: config path does not exist or is not a file: {config_path}",
            file=sys.stderr,
        )
        return 2

    from nautilus.config.loader import ConfigError

    try:
        return asyncio.run(_run_sources(args))
    except ConfigError as exc:
        print(f"ERROR: invalid config: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


# ----------------------------------------------------------------------
# cost-caps
# ----------------------------------------------------------------------


def _fmt_cap_field(value: int | None) -> str:
    """Render an ``int | None`` cap field for the table; ``None`` → ``"-"``."""
    return "-" if value is None else str(value)


def _render_cost_caps_table(
    rows: list[tuple[str, CostCapConfig | None]],
) -> str:
    """Render merged caps per source as a fixed-width plain-text table.

    Columns: ``source_id | max_tokens | max_duration_seconds | max_tool_calls |
    enforcement``. ``None`` fields render as ``"-"``. When the merged cap is
    itself ``None`` (no global + no source override) every numeric column
    renders ``"-"`` and ``enforcement`` falls back to the ``CostCapConfig``
    default of ``"hard"`` (AC-2.9).
    """
    header = (
        f"{'source_id':<20} {'max_tokens':<12} "
        f"{'max_duration_seconds':<20} {'max_tool_calls':<12} {'enforcement':<10}"
    )
    lines: list[str] = [header, "-" * len(header)]
    for source_id, cap in rows:
        if cap is None:
            max_tokens = "-"
            max_duration = "-"
            max_tool_calls = "-"
            enforcement = "hard"
        else:
            max_tokens = _fmt_cap_field(cap.max_tokens)
            max_duration = _fmt_cap_field(cap.max_duration_seconds)
            max_tool_calls = _fmt_cap_field(cap.max_tool_calls)
            enforcement = cap.enforcement
        lines.append(
            f"{source_id:<20} {max_tokens:<12} "
            f"{max_duration:<20} {max_tool_calls:<12} {enforcement:<10}",
        )
    return "\n".join(lines)


async def _run_cost_caps_show(broker: Broker, source_filter: str | None) -> int:
    """Print the merged cost-caps table. Returns process exit code."""
    sources = broker.sources
    global_cap = broker._config.cost_caps  # pyright: ignore[reportPrivateUsage]

    if source_filter is not None:
        match = next((s for s in sources if s.id == source_filter), None)
        if match is None:
            print(
                f"ERROR: unknown source id: {source_filter!r}",
                file=sys.stderr,
            )
            return 2
        rows = [(match.id, _merge_cost_caps(global_cap, match.cost_caps))]
    else:
        rows = [
            (s.id, _merge_cost_caps(global_cap, s.cost_caps))
            for s in sorted(sources, key=lambda s: s.id)
        ]

    print(_render_cost_caps_table(rows))
    return 0


async def _run_cost_caps(args: argparse.Namespace) -> int:
    """Async driver for the ``cost-caps`` subcommand group."""
    from nautilus.core.broker import Broker

    broker = Broker.from_config(Path(args.config))
    try:
        await broker.setup()
        op = args.cost_caps_op
        if op == "show":
            return await _run_cost_caps_show(broker, args.source)
        # argparse enforces required=True; defensive.
        print(f"ERROR: unknown cost-caps operation: {op!r}", file=sys.stderr)
        return 2
    finally:
        with contextlib.suppress(Exception):
            await broker.aclose()


def _cmd_cost_caps(args: argparse.Namespace) -> int:
    """Sync entrypoint for the ``cost-caps`` subcommand group."""
    config_path = Path(args.config)
    if not config_path.is_file():
        print(
            f"ERROR: config path does not exist or is not a file: {config_path}",
            file=sys.stderr,
        )
        return 2

    from nautilus.config.loader import ConfigError

    try:
        return asyncio.run(_run_cost_caps(args))
    except ConfigError as exc:
        print(f"ERROR: invalid config: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


# ----------------------------------------------------------------------
# entry point
# ----------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        return _cmd_version()
    if args.command == "health":
        return _cmd_health(args.url)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "sources":
        return _cmd_sources(args)
    if args.command == "cost-caps":
        return _cmd_cost_caps(args)
    # argparse enforces required=True; this is defensive.
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
