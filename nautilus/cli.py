"""Nautilus CLI — ``serve``/``health``/``version`` subcommands (FR-30, D-15).

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
import sys
import tempfile
import urllib.error
import urllib.request
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import yaml

if TYPE_CHECKING:
    from nautilus.core.broker import Broker

_DEFAULT_HEALTH_URL = "http://localhost:8000/readyz"
_DEFAULT_BIND = "127.0.0.1:8000"
_HEALTH_TIMEOUT_S = 5


def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argparse parser with three subcommands."""
    parser = argparse.ArgumentParser(
        prog="nautilus",
        description="Nautilus reasoning-engine CLI (serve / health / version).",
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
    # argparse enforces required=True; this is defensive.
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
