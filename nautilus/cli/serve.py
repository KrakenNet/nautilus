"""``nautilus serve`` subcommand — runners and config helpers."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import yaml

if TYPE_CHECKING:
    from nautilus.core.broker import Broker

_DEFAULT_BIND = "127.0.0.1:8000"

_log = logging.getLogger(__name__)


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

    try:
        loaded: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError:
        # Same answer as the non-dict case below, for the same reason: this
        # function neutralizes egress fields, it does not validate. Letting the
        # parse error out instead made ``--air-gapped`` the only path where a
        # malformed file escaped ``broker_for_serve``'s refusal wrapper -- so
        # under SIGHUP it reached the reload task raw, with no refusal log line
        # and no ``config_reload_refused`` receipt. Hand it on; from_config
        # raises the ConfigError the operator already knows how to read.
        return config_path
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


async def reload_config(broker: Broker, config_path: Path, *, air_gapped: bool) -> bool:
    """Re-read ``config_path`` and hand the safe subset to ``broker``.

    Validation is :func:`broker_for_serve` -- the same call ``serve`` makes
    before it binds and ``nautilus config check`` makes before a deploy. A
    config ``serve`` would exit 2 on is refused here in byte-identical words,
    because it is refused by the same line of code. It runs on a worker thread
    for the same reason :meth:`Broker.afrom_config` does: reading the YAML and
    compiling the rule tree into a CLIPS environment is blocking, and the
    process is still serving requests while it happens.

    Refusal is total and quiet on the serving side: an audit entry is written,
    a line is logged, and the running config keeps answering untouched. The
    process does not exit -- a bad edit to a mounted ConfigMap must not be a
    way to take a broker down.

    Returns:
        ``True`` when the new file was adopted (including when it was
        equivalent to the running one), ``False`` when it was refused.
    """
    try:
        candidate = await asyncio.to_thread(broker_for_serve, config_path, air_gapped=air_gapped)
    except ConfigRefusedError as exc:
        _refuse_reload(broker, str(exc))
        return False

    from nautilus.core.broker import ConfigNotReloadableError

    try:
        adopted = await broker.reload(candidate)
    except ConfigNotReloadableError as exc:
        _refuse_reload(broker, str(exc))
        return False

    detail = "adopted " + ", ".join(adopted) if adopted else "no reloadable key changed"
    # What the reload cost besides the keys it adopted: exposure ledgers left
    # with nothing to accumulate under, and listeners that did not run. The
    # adopted-key list says a credential changed; it cannot say that a
    # cumulative-exposure budget was cleared with it, and that is the half an
    # audit log has to answer for.
    notes = broker.last_reload_notes
    if notes:
        detail = f"{detail}; " + "; ".join(notes)
    _log.info("SIGHUP: reloaded %s (%s)", config_path, detail)
    broker.emit_reload_event("config_reloaded", detail)
    return True


def _refuse_reload(broker: Broker, reason: str) -> None:
    """Log and audit a refused reload. The running config is not touched."""
    _log.error("SIGHUP: refused; the running config is unchanged. Reason: %s", reason)
    broker.emit_reload_event("config_reload_refused", reason)


def _install_reload_handler(broker: Broker, config_path: Path, *, air_gapped: bool) -> None:
    """Wire ``SIGHUP`` on the running loop to :func:`reload_config`.

    A no-op where the platform has no ``SIGHUP`` or the loop refuses signal
    handlers (Windows, and any loop that is not the main thread's) -- the
    broker serves exactly as it did before, which is the pre-reload behaviour
    and not a failure.

    One reload at a time: a second ``SIGHUP`` arriving while one is in flight
    is dropped rather than queued, because both would read the same file and
    the second would only re-validate what the first already adopted.
    """
    handler = getattr(signal, "SIGHUP", None)
    if handler is None:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:  # pragma: no cover - only reachable off the loop
        return

    in_flight: set[asyncio.Task[bool]] = set()

    def _on_sighup() -> None:
        if in_flight:
            _log.warning("SIGHUP: a reload is already running; ignoring this one")
            return
        task = asyncio.ensure_future(reload_config(broker, config_path, air_gapped=air_gapped))
        in_flight.add(task)
        task.add_done_callback(in_flight.discard)

    try:
        loop.add_signal_handler(handler, _on_sighup)
    except (NotImplementedError, RuntimeError, ValueError):
        _log.debug("SIGHUP reload is unavailable on this platform/loop", exc_info=True)
        return
    _log.info(
        "SIGHUP reloads sources, rules, api.keys and the live session_store limits "
        "from %s; every other key needs a restart",
        config_path,
    )


async def _serve_or_raise(server: Any) -> None:
    """Run a uvicorn server, and treat a startup that never happened as one.

    ``Server.serve()`` does **not** raise when the ASGI lifespan raises: it
    logs "Application startup failed. Exiting.", sets ``should_exit`` and
    returns normally. The CLI then reached its unconditional ``return 0``, so a
    pod whose fail-closed session store was unreachable exited Completed
    instead of CrashLoopBackOff and nothing ever restarted it.
    """
    await server.serve()
    if not server.started:
        raise RuntimeError(
            "application startup failed; the server never accepted a "
            "connection. The cause is logged above."
        )


async def _run_rest(broker: Broker, host: str, port: int, log_level: str = "info") -> None:
    """Run uvicorn against :func:`create_app` with an injected broker."""
    import uvicorn

    from nautilus.transport.fastapi_app import create_app

    app = create_app(None, existing_broker=broker)
    config = uvicorn.Config(app, host=host, port=port, log_level=log_level)
    await _serve_or_raise(uvicorn.Server(config))


async def _run_mcp(
    broker: Broker, mode: str, host: str, port: int, log_level: str = "info"
) -> None:
    """Run FastMCP with the given transport mode and the injected broker."""
    from nautilus.transport.mcp_server import create_server

    mcp = create_server(None, existing_broker=broker)
    # The injected-broker contract (mcp_server docstring) leaves setup()
    # to the caller — idempotent so safe in the --transport both path.
    await broker.setup()

    if mode == "stdio":
        await mcp.run_stdio_async()
        return

    # B4 -- ``run_streamable_http_async`` serves the raw FastMCP app, which has
    # no auth at all. ``http_app`` applies the same X-API-Key gate the REST leg
    # uses, and fails closed when no keys are configured. ``agent_id`` is still
    # taken verbatim from the tool argument (AC-13.3), but a key configured in
    # the ``{key, agent_id, capabilities}`` form may only pass its own agent —
    # with bare-string keys the transport remains the only identity boundary
    # there is, and anyone holding one asserts the highest-clearance agent in
    # the config.
    import uvicorn

    from nautilus.transport.mcp_server import _mcp_settings, http_app

    # A callable, not a snapshot: SIGHUP adopting ``api.keys`` must retire the
    # old credential on this port at the same moment it retires it on REST.
    app = http_app(mcp, api_keys=lambda: _mcp_settings(broker)[2])
    await _serve_or_raise(
        uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level=log_level))
    )


async def _run_both(
    broker: Broker,
    host: str,
    port: int,
    mcp_mode: str,
    log_level: str = "info",
) -> None:
    """Run REST + MCP concurrently on the same asyncio loop (NFR-14).

    The shared ``broker`` singleton satisfies NFR-14 — a single Fathom
    engine and adapter pool backs both transports. MCP http is bound to
    ``port + 1`` so the two servers don't collide on the same socket.
    """
    mcp_port = port + 1 if mcp_mode == "http" else port
    await asyncio.gather(
        _run_rest(broker, host, port, log_level),
        _run_mcp(broker, mcp_mode, host, mcp_port, log_level),
    )


class ConfigRefusedError(Exception):
    """A config ``serve`` will not start on, carrying the words it refuses in.

    The message is everything ``serve`` prints after ``ERROR: ``, so a config
    checked ahead of a deploy and the same config refused at startup read
    identically.
    """


def broker_for_serve(config_path: Path, *, air_gapped: bool) -> Broker:
    """Everything ``serve`` does between the path and the socket.

    Path check, the ``--air-gapped`` pre-pass, and ``Broker.from_config`` —
    the sequence ``nautilus serve`` runs before uvicorn binds, factored out
    so ``nautilus config check`` runs it rather than a second copy of it. A
    reimplementation would drift, and the failure mode of a drifted validator
    is that it blesses a config ``serve`` then refuses, which is worse than
    having no check at all.

    What it deliberately does not reach: ``Broker.setup()``. ``serve`` does
    not call it either until the transport is already up (the FastAPI
    lifespan does), and it is where a durable session store is first dialled
    and adapter schema fingerprints are checked — questions about the
    environment the process lands in, not about the file. Those failures are
    what ``/readyz`` and the rollout's readiness gate are for. Everything the
    file alone decides, including whether ``audit.path`` can be opened for
    writing, is settled here.

    Raises:
        ConfigRefusedError: On any config ``serve`` would exit 2 on.
    """
    if not config_path.is_file():
        raise ConfigRefusedError(f"config path does not exist or is not a file: {config_path}")

    try:
        effective_path = _load_config_for_serve(config_path, air_gapped=air_gapped)
    except RuntimeError as exc:
        raise ConfigRefusedError(str(exc)) from exc

    # Broker.from_config surfaces ConfigError / validation errors with
    # readable messages; the caller turns these into a non-zero exit before
    # any bind.
    from nautilus.config.loader import ConfigError
    from nautilus.core.broker import Broker

    try:
        return Broker.from_config(effective_path)
    except ConfigError as exc:
        raise ConfigRefusedError(f"invalid config: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - surface wiring failures cleanly
        raise ConfigRefusedError(f"broker construction failed: {exc}") from exc


__all__ = [
    "ConfigRefusedError",
    "_install_reload_handler",
    "_DEFAULT_BIND",
    "_enforce_air_gap",
    "_load_config_for_serve",
    "_run_both",
    "_run_mcp",
    "_run_rest",
    "_split_bind",
    "broker_for_serve",
    "reload_config",
]
