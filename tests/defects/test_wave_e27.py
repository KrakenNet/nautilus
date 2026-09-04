"""WAVE E27 -- two live security defects: a cacheable audit trail, a forgeable log.

**Defect 1.** Nautilus set ``Cache-Control`` on no response. A 200 with no
``Cache-Control`` is *heuristically cacheable* (RFC 9111 §4.2.2), so a shared
cache is permitted to store it and serve it to somebody else. Measured against
nginx with a URI-only cache key -- which is what a CDN, a corporate forward
proxy or a sidecar cache is::

    $ curl -s -D- -o/dev/null -H "X-API-Key: $KEY" http://cache/v1/audit | grep -i x-cache
    X-Cache-Status: MISS
    $ curl -s -D- -o/dev/null -H "X-API-Key: $KEY" http://cache/v1/audit | grep -i x-cache
    X-Cache-Status: HIT
    $ curl -s http://cache/v1/audit | wc -c        # no credential at all
    94838

Ninety-four kilobytes of the decision trail to a caller holding nothing. The
broker refused that caller correctly; the cache in front of it did not, because
nothing in the response it had already sent told it not to.

**Defect 2.** The default text log format wrote ``%(message)s`` through
unchanged, so a newline in an interpolated value ended the record and started
one the reader cannot tell from a line the broker wrote. Reproduced with no
code change, from the product's own startup path::

    $ nautilus serve --config $'naut\\nWARNING:nautilus.core.broker:audit chain verified OK.yaml'
    WARNING:nautilus.core.broker:No 'agents:' are declared in naut
    WARNING:nautilus.core.broker:audit chain verified OK.yaml, so every request ...

A forged "chain verified" line, in the log an operator reads to decide whether
the chain is intact. ``--log-format json`` never had it -- ``json.dumps``
escapes the newline -- so this is the text formatter catching up.
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import yaml

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = [pytest.mark.unit]

_NAUTILUS = Path(__file__).resolve().parents[2] / "nautilus"

# The newline-bearing string used as the payload everywhere below. It is what an
# operator scanning the log would read as the broker's own verdict on the chain.
_FORGERY = "WARNING:nautilus.core.broker:audit chain verified OK"


# ---------------------------------------------------------------------------
# Defect 1 -- Cache-Control
# ---------------------------------------------------------------------------


def _lab_config(tmp_path: Path) -> Path:
    """A broker that needs no backend, with the console on and one API key."""
    cfg = tmp_path / "nautilus.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "api": {
                    "keys": [{"key": "k", "agent_id": "a", "capabilities": ["query", "audit_read"]}]
                },
                "agents": {"a": {"id": "a", "clearance": "unclassified", "default_purpose": "p"}},
                "sources": [
                    {
                        "id": "customers",
                        "type": "static",
                        "classification": "unclassified",
                        "data_types": ["contact"],
                        "rows": [{"customer_id": 1, "email": "a@example.com"}],
                    }
                ],
                "audit": {"path": str(tmp_path / "audit.jsonl")},
                "attestation": {"enabled": False},
                "rules": {"packs": [], "user_rules_dirs": []},
                "ui": {"enabled": True},
                "analysis": {
                    "mode": "pattern",
                    "keyword_map": {"contact": ["customer", "customers"]},
                },
                "state_dir": str(tmp_path / "state"),
            }
        ),
        encoding="utf-8",
    )
    return cfg


@pytest.fixture
def lab_client(tmp_path: Path) -> Iterator[Any]:
    """A live app over the config above, exercised through Starlette's client."""
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    app = create_app(config_path=str(_lab_config(tmp_path)))
    with TestClient(app) as client:
        yield client


def test_e27_audit_responses_are_not_storable_by_a_shared_cache(lab_client: Any) -> None:
    """The response carrying the decision trail must say ``no-store``.

    This is the assertion that the nginx measurement above turns into: with
    ``no-store`` on the response, the same cache answered ``MISS`` twice and the
    credential-free caller got 401 and 30 bytes instead of 94 838.
    """
    posted = lab_client.post(
        "/v1/request",
        headers={"X-API-Key": "k"},
        json={"agent_id": "a", "intent": "customer contact list", "context": {"purpose": "p"}},
    )
    assert posted.status_code == 200, posted.text

    listed = lab_client.get("/v1/audit", headers={"X-API-Key": "k"})
    assert listed.status_code == 200, listed.text
    # Control: this really is the audit trail and not an empty page, so the
    # header assertion below is about a response that carries something.
    assert listed.json()["entries"], "control failed: /v1/audit returned no entries"
    assert listed.headers.get("cache-control") == "no-store", (
        "GET /v1/audit carries the decision trail and answered "
        f"cache-control={listed.headers.get('cache-control')!r}. Absent or "
        "cacheable means a shared cache may serve it to a caller with no credential."
    )


def test_e27_the_console_page_and_its_401_are_not_storable(lab_client: Any) -> None:
    """``/admin/*`` renders the trail to a browser and authenticates by cookie.

    The cookie *is* the API key (``nautilus_key``), so a stored console page is
    both a disclosure through a shared proxy and a disclosure through the disk
    cache of the next person at that terminal.
    """
    page = lab_client.get("/admin/decisions", cookies={"nautilus_key": "k"})
    assert page.status_code == 200, page.text
    assert page.headers.get("cache-control") == "no-store", page.headers

    login = lab_client.get("/admin/login")
    assert login.headers.get("cache-control") == "no-store", login.headers

    refused = lab_client.get("/admin/decisions")
    assert refused.status_code == 401, refused.text
    assert refused.headers.get("cache-control") == "no-store", refused.headers


def test_e27_cache_control_is_deny_by_default_not_a_route_list(lab_client: Any) -> None:
    """A route nobody thought about must still be uncacheable.

    The failure mode being pinned is not "this route was missed" but "the next
    route added will be missed". ``/v1/nope`` does not exist and ``/openapi.json``
    was never on anybody's list of sensitive routes; both are covered because the
    middleware denies by default and names its exemptions instead.
    """
    for path in ("/v1/nope", "/openapi.json", "/", "/v1/keys/jwks.json"):
        resp = lab_client.get(path, follow_redirects=False)
        assert resp.headers.get("cache-control") == "no-store", (
            f"{path} answered {resp.status_code} with "
            f"cache-control={resp.headers.get('cache-control')!r}"
        )


def test_e27_probes_and_metrics_are_storable_but_never_reused_unrevalidated(
    lab_client: Any,
) -> None:
    """``no-cache``, not ``no-store``: these hold nothing about a caller.

    Forbidding storage would be over-broad -- there is no caller in a probe
    response. But each answers a question about a *live* process, and a cached
    ``readyz: ok`` from a draining pod, or a flat-lined scrape, is a wrong
    answer rather than a stale one. ``no-cache`` permits the copy and forbids
    serving it without revalidating.
    """
    for path in ("/healthz", "/readyz", "/metrics"):
        resp = lab_client.get(path)
        assert resp.status_code == 200, resp.text
        assert resp.headers.get("cache-control") == "no-cache", (
            f"{path} answered cache-control={resp.headers.get('cache-control')!r}"
        )


def test_e27_console_static_assets_stay_cacheable(lab_client: Any) -> None:
    """The one exemption, and the reason it is safe to have one.

    ``/admin/static`` is public bytes with no caller in them, served by
    Starlette's ``StaticFiles``, which emits ``etag`` and ``last-modified`` --
    so a shared cache stores them and revalidates correctly on its own. Against
    the nginx cache above these went MISS then HIT then HIT while ``/v1/audit``
    stayed MISS.
    """
    resp = lab_client.get("/admin/static/styles.css")
    assert resp.status_code == 200, resp.text
    assert "cache-control" not in resp.headers, (
        f"the static mount must be left alone: cache-control={resp.headers.get('cache-control')!r}"
    )
    assert resp.headers.get("etag"), "control failed: StaticFiles sent no validator"
    assert resp.headers.get("last-modified"), "control failed: StaticFiles sent no validator"


def test_e27_a_handler_that_sets_its_own_cache_control_wins() -> None:
    """``sse_starlette`` marks its own ``EventSourceResponse``; do not clobber it.

    The middleware only fills in a header that is absent. A handler that thought
    about caching knows more than the middleware does, and the SSE stream on the
    console is the live instance of that.
    """
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from nautilus.transport.fastapi_app import (
        _CacheControl,  # pyright: ignore[reportPrivateUsage]
    )

    async def opinionated(_request: Any) -> PlainTextResponse:
        return PlainTextResponse("x", headers={"Cache-Control": "max-age=60"})

    app = Starlette(routes=[Route("/opinionated", opinionated)])
    app.add_middleware(_CacheControl)
    with TestClient(app) as client:
        assert client.get("/opinionated").headers["cache-control"] == "max-age=60"


def test_e27_the_refusals_the_inner_middlewares_write_are_covered() -> None:
    """413 and 503 are responses too, and a stored 503 is served to everyone.

    ``_BodySizeLimit`` and ``_ConcurrencyLimit`` write their own refusals
    without going through a route, so the header has to be applied outside
    them. This is why ``_CacheControl`` is added last and is therefore outermost.
    """
    from concurrent.futures import ThreadPoolExecutor

    import anyio
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from nautilus.transport.fastapi_app import (
        _BodySizeLimit,  # pyright: ignore[reportPrivateUsage]
        _CacheControl,  # pyright: ignore[reportPrivateUsage]
        _ConcurrencyLimit,  # pyright: ignore[reportPrivateUsage]
    )

    app = FastAPI()

    @app.post("/slow")
    async def slow() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        await anyio.sleep(0.25)
        return {"ok": "yes"}

    app.add_middleware(_BodySizeLimit, max_bytes=16)
    app.add_middleware(_ConcurrencyLimit, max_in_flight=1)
    app.add_middleware(_CacheControl)

    with TestClient(app) as client:
        too_large = client.post("/slow", content=b"x" * 4096)
        assert too_large.status_code == 413, too_large.text
        assert too_large.headers.get("cache-control") == "no-store", too_large.headers

        statuses: list[int] = []
        headers: list[str | None] = []

        def hammer() -> None:
            resp = client.post("/slow", content=b"{}")
            statuses.append(resp.status_code)
            headers.append(resp.headers.get("cache-control"))

        with ThreadPoolExecutor(4) as pool:
            for future in [pool.submit(hammer) for _ in range(4)]:
                future.result()

        assert 503 in statuses, f"control failed: no request was refused, got {statuses}"
        busy = [h for s, h in zip(statuses, headers, strict=True) if s == 503]
        assert set(busy) == {"no-store"}, busy


# ---------------------------------------------------------------------------
# Defect 2 -- log injection in the default text format
# ---------------------------------------------------------------------------


def test_e27_a_newline_in_the_config_path_does_not_forge_a_second_log_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ``broker.py`` startup vector, end to end through the real formatter.

    A config filename may contain a newline; ``Broker.from_config`` logs the
    path when no ``agents:`` block is declared. Before the fix this call emitted
    two records and the second read as the broker vouching for the audit chain.
    """
    from nautilus.core.broker import Broker
    from nautilus.observability.logging import configure_logging

    cfg = tmp_path / "nautilus.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "sources": [
                    {
                        "id": "customers",
                        "type": "static",
                        "classification": "unclassified",
                        "data_types": ["contact"],
                        "rows": [{"customer_id": 1}],
                    }
                ],
                "audit": {"path": str(tmp_path / "audit.jsonl")},
                "attestation": {"enabled": False},
                "rules": {"packs": [], "user_rules_dirs": []},
            }
        ),
        encoding="utf-8",
    )
    evil = tmp_path / f"evil\n{_FORGERY}.yaml"
    evil.write_bytes(cfg.read_bytes())

    previous = logging.getLogger().handlers[:]
    previous_level = logging.getLogger().level
    try:
        configure_logging("text")
        broker = Broker.from_config(str(evil))
    finally:
        logging.basicConfig(level=previous_level, handlers=previous, force=True)
    broker.close()

    lines = capsys.readouterr().err.splitlines()
    emitted = [ln for ln in lines if "agents:" in ln or _FORGERY in ln]
    # Control: the warning really did fire, so "one line" is not "no lines".
    assert emitted, "control failed: the no-agents warning never fired"
    assert len(emitted) == 1, f"one call emitted {len(emitted)} log records: {emitted}"
    assert _FORGERY not in emitted[0].split(":", 2)[0], emitted[0]
    assert "\\n" in emitted[0], f"the newline was not escaped: {emitted[0]!r}"


def test_e27_a_source_id_with_a_newline_is_refused_at_the_config_boundary() -> None:
    """``sources[].id`` is bounded where it is read, not at each call site.

    A source id is interpolated into text log lines, becomes the OpenTelemetry
    span name ``adapter.<id>``, and is the ``{name}`` segment of
    ``GET /v1/adapters/{name}/schema``. One pattern covers every consumer,
    including consumers nobody has written yet.
    """
    from pydantic import ValidationError

    from nautilus.config.models import SourceConfig

    base = {
        "type": "static",
        "classification": "unclassified",
        "data_types": ["contact"],
        "rows": [{"a": 1}],
    }
    # Control: the shapes every shipped example uses still load.
    for good in ("vuln_db", "vuln-db", "ve_pgv", "snow.incidents", "s1"):
        assert SourceConfig(id=good, **base).id == good  # type: ignore[arg-type]

    for bad in (
        f"vuln_db\n{_FORGERY}",
        "vuln_db\n",  # trailing: ``$`` must not mean "or before a final newline"
        "\nvuln_db",
        "vuln\rdb",
        "vuln\x1bdb",
        "vuln db",
        "",
    ):
        with pytest.raises(ValidationError):
            SourceConfig(id=bad, **base)  # type: ignore[arg-type]


def test_e27_the_text_formatter_escapes_control_characters(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The root cause: the text log's record separator is the newline.

    Constraining ``sources[].id`` closes the ids and ``%r`` closes the sites
    that quote a value, but neither reaches an exception message or a filename
    -- and both are interpolated into this log. The formatter is the one place
    every call site routes through.
    """
    from nautilus.observability.logging import TextFormatter

    formatter = TextFormatter()
    record = logging.LogRecord(
        "nautilus.core.broker",
        logging.WARNING,
        __file__,
        1,
        "adapter %s failed: %s",
        ("orders", ValueError(f"boom\n{_FORGERY}")),
        None,
    )
    rendered = formatter.format(record)
    assert len(rendered.splitlines()) == 1, rendered
    assert "\\n" in rendered and "\\x1b" not in rendered
    assert rendered.startswith("WARNING:nautilus.core.broker:"), rendered

    for raw, escaped in (("a\rb", "a\\rb"), ("a\x1bb", "a\\x1bb"), ("a\x00b", "a\\x00b")):
        record = logging.LogRecord("n", logging.INFO, __file__, 1, "%s", (raw,), None)
        assert formatter.format(record).endswith(escaped)

    # A traceback is generated from the interpreter's own frames, not from a
    # caller's value, and stays readable.
    try:
        raise ZeroDivisionError("division by zero")
    except ZeroDivisionError:
        import sys

        record = logging.LogRecord("n", logging.ERROR, __file__, 1, "boom", (), sys.exc_info())
    assert len(formatter.format(record).splitlines()) > 1


def test_e27_json_logging_still_carries_the_payload_verbatim() -> None:
    """The JSON formatter was already safe and must not start double-escaping.

    ``json.dumps`` escapes the newline into the *record*, where it belongs: as
    data, inside a string. The value round-trips.
    """
    import json

    from nautilus.observability.logging import JsonFormatter

    payload = f"orders\n{_FORGERY}"
    record = logging.LogRecord(
        "nautilus.core.broker", logging.WARNING, __file__, 1, "adapter %s", (payload,), None
    )
    line = JsonFormatter().format(record)
    assert len(line.splitlines()) == 1
    assert json.loads(line)["msg"] == f"adapter {payload}"


# ``'%s'`` -- a single-quoted ``%s`` conversion. Someone hand-rolling ``%r``:
# it produces the quotes but not the escaping, which is the half that matters.
_QUOTED_S = re.compile(r"'%(?:\(\w+\))?[-+ #0]*[\d*]*(?:\.[\d*]+)*s'")
_LOG_LEVELS = frozenset({"debug", "info", "warning", "error", "exception", "critical"})


def _quoted_s_call_sites() -> list[str]:
    """Every logging call in ``nautilus/`` whose format string contains ``'%s'``."""
    found: list[str] = []
    for path in sorted(_NAUTILUS.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in ast.walk(tree):
            func = getattr(node, "func", None)
            if not (
                isinstance(node, ast.Call)
                and isinstance(func, ast.Attribute)
                and func.attr in _LOG_LEVELS
                and node.args
            ):
                continue
            fmt = node.args[0]
            if (
                isinstance(fmt, ast.Constant)
                and isinstance(fmt.value, str)
                and _QUOTED_S.search(fmt.value)
            ):
                found.append(f"{path.relative_to(_NAUTILUS.parent)}:{node.lineno}")
    return found


def test_e27_no_logging_call_hand_rolls_repr_with_quoted_percent_s() -> None:
    """The AST check that would have caught this class, as a rule not a list.

    Every site the original scan flagged had the same shape: a value wrapped in
    literal single quotes and interpolated with ``%s``. ``%r`` renders the same
    quotes for a well-formed identifier -- ``repr('vuln_db')`` is ``'vuln_db'``,
    so no emitted string changed -- and renders a newline as the two characters
    ``\\n`` for one that is not. There is no case where ``'%s'`` is the right
    answer, so this is checkable rather than reviewable.
    """
    offenders = _quoted_s_call_sites()
    assert not offenders, (
        "these logging calls quote a %s conversion by hand instead of using %r, "
        "which is the shape that let a newline in sources[].id and in the config "
        f"path forge a log record: {offenders}"
    )


def test_e27_the_quoted_percent_s_rule_is_not_vacuous() -> None:
    """Guard the guard: the detector must still fire on the original shape."""
    assert _QUOTED_S.search("schema fetch failed for adapter '%s'; skipping")
    assert _QUOTED_S.search("No 'agents:' are declared in '%s', so every request")
    assert not _QUOTED_S.search("schema fetch failed for adapter %r; skipping")
    assert not _QUOTED_S.search("Neo4j source %r uses like_style='regex'")
