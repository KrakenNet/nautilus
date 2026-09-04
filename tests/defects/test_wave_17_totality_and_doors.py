# pyright: reportPrivateUsage=false
"""WAVE 17 -- what an adversarial pass found wrong with WAVE 15 and WAVE 16.

Three of these are defects in the fixes themselves: a guard that catches one
exception class where the job is to catch all of them, a refusal that names two
causes and can only reach one, and a regression test weak enough that a comment
satisfies it. The rest are doors and doc claims those waves missed.
"""

from __future__ import annotations

import asyncio
import inspect
import re
from pathlib import Path

import pytest

from nautilus.core import broker as broker_mod

REPO = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# The fifth and sixth doors to the source catalogue.
# ---------------------------------------------------------------------------


def test_w17_the_adapters_routes_filter_by_clearance_like_every_other_door() -> None:
    """``GET /v1/adapters`` published the catalogue whole under ``query``.

    WAVE 15 said four surfaces publish the source catalogue and that all four
    now trim to ``sources_visible_to``. There were six. ``/v1/adapters`` and
    ``/v1/adapters/{name}/schema`` carry the same ``query`` capability as
    ``/v1/sources`` -- ``query`` is the *default* for a structured key -- and
    read ``broker.sources`` whole, handing a caller the id, type and quarantine
    state of sources the rule ladder denies it, plus the internal ``host:port``
    and reachability under ``?probe=true``.
    """
    from nautilus.transport import fastapi_app

    source = inspect.getsource(fastapi_app)
    listing = source.split('\n        "/v1/adapters",')[1].split("@app.get(")[0]
    assert "sources_visible_to" in listing, (
        "GET /v1/adapters reads broker.sources whole; it is gated on `query`, "
        "the same capability /v1/sources filters under"
    )


@pytest.mark.parametrize(
    ("module", "reader"),
    [
        ("nautilus.transport.fastapi_app", "sources_visible_to"),
        ("nautilus.ui.router", "sources_visible_to"),
        ("nautilus.ui.sse", "sources_visible_to"),
        ("nautilus.transport.mcp_server", "sources_visible_to"),
    ],
)
def test_w17_no_door_reads_the_catalogue_whole(module: str, reader: str) -> None:
    """Assert on the *read*, not on the file containing the word somewhere.

    WAVE 15's guard was ``"sources_visible_to" in path.read_text()`` per file.
    ``sources_visible_to`` appears in a *comment* in two of those files, so the
    guard passed with the real filtered read deleted -- measured. And
    ``fastapi_app.py`` satisfied it at line 832 while line 1198 leaked. A guard
    that a comment can satisfy is not a guard.
    """
    import importlib

    source = inspect.getsource(importlib.import_module(module))
    # Strip comments and docstrings: only executable reads count.
    code = "\n".join(
        line.split("#")[0] for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    code = re.sub(r'"""[\s\S]*?"""', "", code)
    reads = re.findall(r"\bbroker\.sources\b(?!_)", code) + re.findall(
        r"\bself\._broker\.sources\b(?!_)", code
    )
    assert not reads, (
        f"{module} reads the source catalogue whole {len(reads)} time(s); "
        f"every door must go through {reader}"
    )
    assert reader in code, f"{module} never calls {reader} outside a comment"


# ---------------------------------------------------------------------------
# Totality: a probe and a config guard must catch every class, not one more.
# ---------------------------------------------------------------------------


def test_w17_a_port_out_of_range_is_a_probe_failure_not_a_500() -> None:
    """WAVE 16 widened ``except OSError`` to ``UnicodeError``. Still not total.

    ``open_connection`` with a port above 65535 raises ``OverflowError``, an
    ``ArithmeticError`` -- so it escapes both. ``aprobe_source`` is one source's
    whole answer and is gathered across all of them, so anything it lets out
    500s the endpoint and discards every healthy sibling. The fix is not a
    third class in the tuple; it is that this function must be total.
    """

    async def _run() -> None:
        await asyncio.wait_for(broker_mod._dial("127.0.0.1", 99999, "postgres"), 3)

    with pytest.raises(OverflowError):
        asyncio.run(_run())  # the raw dial really does raise it

    source = inspect.getsource(broker_mod.Broker.aprobe_source)
    assert "except Exception" in source, (
        "aprobe_source enumerates exception classes; a probe that is gathered "
        "across every source has to be total"
    )


def test_w17_broker_for_serve_is_total_on_the_air_gapped_path() -> None:
    """``--air-gapped`` re-serialises and writes a temp file, both unguarded.

    WAVE 16 wrapped ``yaml.safe_load`` only. ``yaml.safe_dump`` (twice),
    ``_enforce_air_gap`` and ``NamedTemporaryFile`` sit after it with nothing
    around them, and ``broker_for_serve`` catches only ``RuntimeError`` from the
    call. Anything else still reaches the SIGHUP task raw: no refusal log line
    and no ``config_reload_refused`` receipt. ``broker_for_serve``'s documented
    job is to raise ``ConfigRefusedError`` on anything ``serve`` would exit 2
    on, so it should catch by that contract, not by class.
    """
    from nautilus.cli import serve as serve_mod

    body = inspect.getsource(serve_mod.broker_for_serve)
    loader_guard = body.split("_load_config_for_serve")[1].split("from nautilus.config")[0]
    assert "except Exception" in loader_guard, (
        "broker_for_serve catches only RuntimeError from the loader, so the "
        "air-gap rewrite's own failures escape as themselves"
    )


def test_w17_an_unguarded_reload_failure_still_writes_a_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever the loader raises, SIGHUP must refuse rather than escape."""
    from nautilus.cli import serve as serve_mod

    def _boom(*_a: object, **_k: object) -> Path:
        raise MemoryError("anything at all")

    monkeypatch.setattr(serve_mod, "_load_config_for_serve", _boom)
    config = tmp_path / "n.yaml"
    config.write_text("sources: []\n", encoding="utf-8")
    with pytest.raises(serve_mod.ConfigRefusedError):
        serve_mod.broker_for_serve(config, air_gapped=True)


# ---------------------------------------------------------------------------
# The audit refusal names two causes and could only reach one.
# ---------------------------------------------------------------------------


def test_w17_a_mounted_but_unwritable_audit_dir_gets_the_named_refusal(
    tmp_path: Path,
) -> None:
    """``mkdir(exist_ok=True)`` succeeds on a directory that exists.

    So the WAVE 16 wrapper fires only for the *missing* volume. The second
    cause its own sentence names -- a mount UID 65532 cannot write -- takes a
    different path entirely (opening the file) and still refused with a bare
    ``[Errno 13] Permission denied: '.../audit.jsonl'``. Measured.
    """
    from nautilus.cli.serve import ConfigRefusedError, broker_for_serve

    mounted = tmp_path / "nautilus"
    mounted.mkdir()
    mounted.chmod(0o500)
    try:
        (mounted / "probe").touch()
    except OSError:
        pass
    else:  # pragma: no cover - root, or a filesystem without modes
        pytest.skip("this filesystem still let the directory be written")

    config = tmp_path / "n.yaml"
    config.write_text(f"sources: []\naudit:\n  path: {mounted}/audit.jsonl\n", encoding="utf-8")
    with pytest.raises(ConfigRefusedError) as caught:
        broker_for_serve(config, air_gapped=False)
    message = str(caught.value)
    assert "audit log" in message, (
        f"a mounted-but-unwritable audit volume still refuses with a bare errno: {message}"
    )
    assert "not writable" in message


# ---------------------------------------------------------------------------
# Two smaller honesty problems in the probe.
# ---------------------------------------------------------------------------


def test_w17_the_no_hello_branch_is_not_marked_unreachable() -> None:
    """It is reachable: any scheme reaches ``_dial`` when the DSN names a port.

    ``_DEFAULT_PORTS`` is consulted only when ``parts.port`` is absent, so
    ``s3://host:443`` or any other scheme with an explicit port lands in
    ``_dial`` with no hello. Marking that branch ``# pragma: no cover`` claims
    it cannot happen and hides it from coverage.
    """
    source = inspect.getsource(broker_mod._dial)
    branch = source.split("if hello is None:")[1].split("\n")[0]
    assert "pragma: no cover" not in branch, (
        "the no-hello branch is reachable through any scheme whose DSN names an explicit port"
    )


def test_w17_the_tls_note_does_not_claim_a_cause_it_did_not_establish() -> None:
    """``ssl.SSLError`` is not only "we refused their certificate".

    ``WRONG_VERSION_NUMBER`` (TLS spoken at a plaintext port) and a server-side
    mTLS rejection both arrive as ``SSLError``, and neither is this process
    refusing a certificate. Report the handshake failure and let the text of
    the error say which one it was.
    """
    source = inspect.getsource(broker_mod._dial)
    assert "refused its certificate" not in source, (
        "the note names one cause for an exception class that has several"
    )


# ---------------------------------------------------------------------------
# Doc claims those waves left behind.
# ---------------------------------------------------------------------------


def test_w17_the_deploy_guide_says_the_same_thing_in_both_tables() -> None:
    """WAVE 16 corrected §10's row and left §5's table promising the old 503."""
    guide = (REPO / "docs" / "how-to" / "deploying.md").read_text(encoding="utf-8")
    volumes_row = [line for line in guide.splitlines() if line.startswith("| `/var/log/nautilus`")]
    assert volumes_row, "the volumes table no longer has a /var/log/nautilus row"
    assert "never becomes ready" not in volumes_row[0], (
        "the volumes table still promises a readiness failure for a volume "
        "that refuses startup before anything binds"
    )


def test_w17_the_rest_api_page_documents_the_sse_streams_real_auth() -> None:
    """WAVE 15 put a ``query`` capability on ``/admin/sources/events``.

    The reference page still described the route as it behaved before.
    """
    page = (REPO / "docs" / "reference" / "rest-api.md").read_text(encoding="utf-8")
    section = page.split("### `GET /admin/sources/events`")[1].split("\n### ")[0]
    assert "query" in section, (
        "rest-api.md does not say /admin/sources/events requires the query "
        "capability, which WAVE 15 gave it"
    )
