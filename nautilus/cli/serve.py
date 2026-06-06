"""``nautilus serve`` subcommand — runners and config helpers."""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import yaml

if TYPE_CHECKING:
    from nautilus.core.broker import Broker

_DEFAULT_BIND = "127.0.0.1:8000"


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


def _is_loopback_host(url: str) -> bool:
    """True when ``url``'s host is a loopback address (or ``localhost``)."""
    import ipaddress
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname
    if not host:
        return False
    host = host.rstrip(".")  # FQDN trailing dot: "localhost." is loopback too
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _enforce_air_gap(raw: dict[str, Any]) -> dict[str, Any]:
    """Mutate ``raw`` YAML dict for ``--air-gapped``; emit WARN on each override.

    Overrides ``analysis.mode`` to ``"pattern"``, drops
    ``analysis.provider`` (NFR-1, AC-15.3), and removes any ``type: llm``
    source whose ``connection`` host is not loopback (#43): an LLM source
    is only air-gap compatible when the inference server is local.
    Non-destructive on configs that already conform (no WARN emitted in
    that case).
    """
    sources_raw = raw.get("sources")
    if isinstance(sources_raw, list):
        kept: list[Any] = []
        for entry in cast("list[Any]", sources_raw):
            if (
                isinstance(entry, dict)
                and cast("dict[str, Any]", entry).get("type") == "llm"
                and not _is_loopback_host(str(cast("dict[str, Any]", entry).get("connection", "")))
            ):
                entry_dict = cast("dict[str, Any]", entry)
                print(
                    f"WARN: --air-gapped drops LLM source "
                    f"id={entry_dict.get('id')!r} — connection host is not "
                    f"loopback (NFR-1, #43)",
                    file=sys.stderr,
                )
                continue
            kept.append(entry)
        raw["sources"] = kept

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


__all__ = [
    "_DEFAULT_BIND",
    "_enforce_air_gap",
    "_load_config_for_serve",
    "_run_both",
    "_run_mcp",
    "_run_rest",
    "_split_bind",
]
