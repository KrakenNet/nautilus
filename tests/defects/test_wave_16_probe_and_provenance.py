# pyright: reportPrivateUsage=false
"""WAVE 16 -- six findings an adversarial pass raised against waves 13-15.

Every test here was watched fail for its own reason before the fix landed.
The shared theme is a surface that reports success it did not establish: a
probe that never asked, a reload that refused without saying so, a stamp
that fell back to something a caller controls.
"""

from __future__ import annotations

import asyncio
import inspect
import socket
import threading
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml

from nautilus.core import broker as broker_mod

if TYPE_CHECKING:
    from collections.abc import Iterator


# ---------------------------------------------------------------------------
# H3a -- bolt/neo4j had no hello, so a listener that never answers read green.
# ---------------------------------------------------------------------------


@pytest.fixture
def deaf_listener() -> Iterator[tuple[str, int]]:
    """A socket that accepts a connection and then says nothing at all.

    The exact shape ``_PROBE_HELLO``'s own comment describes: the kernel
    completes the handshake into a backlog the process never drains.
    """
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    host, port = sock.getsockname()
    accepted: list[socket.socket] = []
    stop = threading.Event()

    def _accept() -> None:
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except (TimeoutError, OSError):
                continue
            accepted.append(conn)  # held open, never written to

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    try:
        yield host, port
    finally:
        stop.set()
        thread.join(timeout=2)
        for conn in accepted:
            conn.close()
        sock.close()


@pytest.mark.parametrize("scheme", ["bolt", "neo4j"])
def test_w16_a_graph_listener_that_never_answers_is_not_reachable(
    deaf_listener: tuple[str, int], scheme: str
) -> None:
    """``bolt`` and ``neo4j`` must require a reply, exactly as postgres does."""
    host, port = deaf_listener

    async def _run() -> None:
        await asyncio.wait_for(broker_mod._dial(host, port, scheme), 2.0)

    with pytest.raises((ConnectionResetError, TimeoutError)):
        asyncio.run(_run())


@pytest.mark.parametrize("scheme", sorted(broker_mod._DEFAULT_PORTS))
def test_w16_every_probeable_scheme_has_a_hello_to_send(scheme: str) -> None:
    """A scheme with a default port is a scheme the probe claims to answer for.

    A port with no hello is the false green: ``_dial`` returns before it has
    asked anything, and the caller reports ``reachable=True``.
    """
    assert scheme in broker_mod._PROBE_HELLO, (
        f"{scheme!r} has a default port but no hello, so its probe reports "
        f"reachable=True without waiting for a reply"
    )


# ---------------------------------------------------------------------------
# H3b -- a rejected certificate read as an unqualified green.
# ---------------------------------------------------------------------------


def test_w16_a_refused_certificate_is_reported_not_swallowed() -> None:
    """TLS the process will not accept must reach the operator as a detail.

    The reachability answer stays ``True`` -- the server did reply -- but a
    probe that returns ``detail=None`` tells an operator the source is fine
    when this broker cannot open a usable connection to it.
    """
    source = inspect.getsource(broker_mod._dial)
    assert "except ssl.SSLError" in source
    handler = source.split("except ssl.SSLError")[1].split("\n", 2)[1]
    assert handler.strip() != "return", (
        "a refused certificate returns with no note, so aprobe_source reports "
        "reachable=True and detail=None"
    )


def test_w16_the_ssl_note_reaches_the_probe_result() -> None:
    """``aprobe_source`` must carry ``_dial``'s note into ``SourceProbe.detail``."""
    assert inspect.signature(broker_mod._dial).return_annotation == "str | None"
    caller = inspect.getsource(broker_mod.Broker.aprobe_source)
    assert "SourceProbe(endpoint, True, None)" not in caller, (
        "aprobe_source hardcodes detail=None, discarding whatever _dial found"
    )


# ---------------------------------------------------------------------------
# M1 -- a hostname that will not encode is not an OSError.
# ---------------------------------------------------------------------------


def test_w16_an_unencodable_host_is_a_probe_failure_not_a_500() -> None:
    """``UnicodeEncodeError`` is a ``ValueError``, so ``except OSError`` missed it.

    ``GET /v1/adapters?probe=true`` gathers every source's probe. One source
    raising past ``aprobe_source`` discarded the results for every healthy
    sibling and answered 500.
    """
    source = inspect.getsource(broker_mod.Broker.aprobe_source)
    assert "UnicodeError" in source or "ValueError" in source, (
        "aprobe_source catches OSError only; a host that will not encode "
        "raises UnicodeEncodeError straight through it"
    )


# ---------------------------------------------------------------------------
# H2 -- --air-gapped parsed the YAML itself and let the parse error escape.
# ---------------------------------------------------------------------------


def test_w16_air_gapped_refuses_bad_yaml_the_same_way_plain_serve_does(
    tmp_path: Path,
) -> None:
    """The same broken file must be refused identically with and without the flag.

    ``--air-gapped`` re-reads the config to neutralise egress fields. It
    parsed the YAML outside the guard that turns a bad config into a named
    refusal, so under SIGHUP a malformed file escaped as a raw
    ``yaml.ParserError``: no log line, no ``config_reload_refused`` receipt,
    and the operator saw nothing at all.
    """
    from nautilus.cli.serve import ConfigRefusedError, broker_for_serve

    bad = tmp_path / "bad.yaml"
    bad.write_text("sources: [\n  - id: unclosed\n", encoding="utf-8")

    with pytest.raises(ConfigRefusedError):
        broker_for_serve(bad, air_gapped=False)
    with pytest.raises(ConfigRefusedError):
        broker_for_serve(bad, air_gapped=True)


def test_w16_air_gapped_yaml_errors_do_not_escape_the_loader(tmp_path: Path) -> None:
    """``_load_config_for_serve`` hands an unparseable file on, as it does a non-dict."""
    from nautilus.cli.serve import _load_config_for_serve

    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [1, 2\nb: {\n", encoding="utf-8")
    try:
        assert _load_config_for_serve(bad, air_gapped=True) == bad
    except yaml.YAMLError as exc:  # pragma: no cover - the defect itself
        pytest.fail(f"the parse error escaped the loader: {exc!r}")


# ---------------------------------------------------------------------------
# M3 -- an unreadable stamp fell back to an environment variable.
# ---------------------------------------------------------------------------


def test_w16_an_unreadable_stamp_does_not_fall_back_to_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stamp that exists but cannot be read must never be overridden.

    ``_stamped`` returned ``None`` for every ``OSError``, which is the same
    answer it gives for a wheel that was never stamped -- so a mode-000 stamp
    handed provenance to ``NAUTILUS_BUILD_REV``, which any caller who can set
    the process environment controls.
    """
    from nautilus import build as build_mod

    stamp = tmp_path / "BUILD_REV"
    stamp.write_text("real-revision\n", encoding="utf-8")
    stamp.chmod(0o000)
    try:
        stamp.read_text(encoding="utf-8")
    except OSError:
        pass
    else:  # pragma: no cover - root, or a filesystem without modes
        pytest.skip("this filesystem still let the stamp be read")

    monkeypatch.setattr(build_mod, "STAMP_PATH", stamp)
    monkeypatch.setenv(build_mod.BUILD_REV_ENV, "attacker-supplied")
    assert build_mod.build_rev() == build_mod.UNKNOWN


# ---------------------------------------------------------------------------
# M2 -- the orphan warning indexed a file the operator was not looking at.
# ---------------------------------------------------------------------------


def test_w16_the_orphan_warning_says_which_file_it_is_indexing() -> None:
    """``api.keys[3]`` is ambiguous when the operator just edited the file.

    The positions enumerate the *old* config; the operator is reading the new
    one they wrote. Name the file the index belongs to.
    """
    source = inspect.getsource(broker_mod._warn_about_orphaned_ledgers)
    assert 'f"api.keys[{index}]' not in source, (
        "the warning names a position without saying which config it indexes"
    )
    assert "the config it replaced" in source or "old api.keys" in source


# ---------------------------------------------------------------------------
# H1 -- a missing audit volume refused with a bare errno.
# ---------------------------------------------------------------------------


def test_w16_an_unopenable_audit_directory_says_what_it_was_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal must name the audit log, not just the path that failed.

    Measured in the shipped image: a missing ``audit`` volumeMount lands on
    ``/var/log``, which exists and which UID 65532 cannot write, so startup
    refuses with ``[Errno 13]`` before anything binds. An operator reading the
    deployment guide went to ``/readyz`` for this, and nothing was listening.
    """
    from nautilus.cli.serve import ConfigRefusedError, broker_for_serve

    blocked = tmp_path / "blocked"
    blocked.mkdir()
    blocked.chmod(0o500)
    try:
        (blocked / "probe").mkdir()
    except OSError:
        pass
    else:  # pragma: no cover - root, or a filesystem without modes
        pytest.skip("this filesystem still let the directory be created")

    config = tmp_path / "n.yaml"
    config.write_text(
        f"sources: []\naudit:\n  path: {blocked}/nautilus/audit.jsonl\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigRefusedError) as caught:
        broker_for_serve(config, air_gapped=False)
    message = str(caught.value)
    assert "audit log directory" in message
    assert "not mounted" in message and "not writable" in message


def test_w16_the_deploy_guide_does_not_promise_a_probe_that_cannot_run() -> None:
    """A never-mounted audit volume never reaches ``/readyz``; the guide said it did."""
    guide = (Path(__file__).resolve().parents[2] / "docs" / "how-to" / "deploying.md").read_text(
        encoding="utf-8"
    )
    assert "| the `audit` volumeMount is missing |" not in guide, (
        "the guide sends the operator to /readyz for a failure that refuses "
        "startup before any port is bound"
    )
    assert "### 11.5 When the audit volume is missing" in guide
