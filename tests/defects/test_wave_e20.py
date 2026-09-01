# pyright: reportPrivateUsage=false
"""WAVE E20 — three credentials and receipts that travelled in the clear, quietly.

Each one was accepted behaviour that said nothing about itself:

* ``/admin/login`` set ``nautilus_key`` -- which *is* the API key -- without
  ``Secure``, so the browser offered a live credential on any plaintext request
  to the host.
* ``attestation.sink.url`` took ``http://`` to any host and posted signed
  decision receipts to it without a word.
* ``session_store.dsn`` fell back to the ``TEST_PG_DSN`` env var, so deleting the
  key from a ConfigMap repointed the session store at whatever a stray test
  variable held.

The last two stay permitted -- a collector on a private link and the integration
fixtures are both real -- but they are no longer silent. The first is a straight
fix: the cookie is marked ``Secure`` when the request arrived over TLS, and left
unmarked otherwise so a local plaintext console still works.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]


def _config(path: Path) -> str:
    document: dict[str, Any] = {
        "sources": [
            {
                "id": "orders",
                "type": "static",
                "description": "order rows",
                "classification": "unclassified",
                "data_types": ["orders"],
                "rows": [{"order_id": 1}],
            }
        ],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(path / "audit.jsonl")},
        "api": {"keys": ["secret-key"], "auth": {"mode": "api_key"}},
        "ui": {"enabled": True},
    }
    config = path / "nautilus.yaml"
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(config)


def _client(config: str, *, base_url: str = "http://testserver") -> Any:
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    return TestClient(create_app(config), base_url=base_url)


# ---------------------------------------------------------------------------
# 1 -- the admin cookie
# ---------------------------------------------------------------------------


def test_e20_the_admin_cookie_is_secure_over_tls(tmp_path: Path) -> None:
    """The pin. The cookie is the API key; over TLS it must not leak to http."""
    with _client(_config(tmp_path), base_url="https://testserver") as client:
        resp = client.post(
            "/admin/login", data={"api_key": "secret-key"}, follow_redirects=False
        )

    assert resp.status_code == 302, resp.text
    cookie = resp.headers.get("set-cookie", "")
    assert "nautilus_key=" in cookie, cookie
    assert "Secure" in cookie, (
        f"the admin cookie carries a live API key and was set without Secure, so "
        f"the browser offers it on any plaintext request to the host: {cookie}"
    )


def test_e20_the_admin_cookie_honours_a_terminating_proxy(tmp_path: Path) -> None:
    """The pin, as the shipped deployments actually run it.

    TLS terminates at the ingress, so the app sees ``http`` and only
    ``X-Forwarded-Proto`` knows better. Reading the scheme alone would leave
    every deploy/ manifest unprotected.
    """
    with _client(_config(tmp_path)) as client:
        resp = client.post(
            "/admin/login",
            data={"api_key": "secret-key"},
            headers={"X-Forwarded-Proto": "https"},
            follow_redirects=False,
        )

    assert "Secure" in resp.headers.get("set-cookie", ""), resp.headers.get("set-cookie", "")


def test_e20_a_plaintext_console_still_gets_a_usable_cookie(tmp_path: Path) -> None:
    """Control. A Secure cookie over http is dropped, which is a login loop."""
    with _client(_config(tmp_path)) as client:
        resp = client.post(
            "/admin/login", data={"api_key": "secret-key"}, follow_redirects=False
        )

    cookie = resp.headers.get("set-cookie", "")
    assert "nautilus_key=" in cookie, cookie
    assert "Secure" not in cookie, cookie
    assert "HttpOnly" in cookie, cookie


# ---------------------------------------------------------------------------
# 2 -- the attestation sink
# ---------------------------------------------------------------------------


def test_e20_a_plaintext_attestation_sink_says_so(caplog: pytest.LogCaptureFixture) -> None:
    """The pin. Signed receipts crossing the network unencrypted, in silence."""
    from nautilus.core.attestation_sink import HttpAttestationSink

    with caplog.at_level(logging.WARNING, logger="nautilus.core.attestation_sink"):
        HttpAttestationSink("http://collector.internal:9000/attestations")

    assert any("plaintext" in r.message.lower() for r in caplog.records), (
        f"a plaintext sink URL was accepted without a word: {[r.message for r in caplog.records]}"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://collector.internal:9000/attestations",
        "http://localhost:9000/attestations",
        "http://127.0.0.1:9000/attestations",
    ],
)
def test_e20_tls_and_loopback_sinks_stay_quiet(
    url: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Control. Warning on a sink that leaks nothing trains operators to ignore it."""
    from nautilus.core.attestation_sink import HttpAttestationSink

    with caplog.at_level(logging.WARNING, logger="nautilus.core.attestation_sink"):
        HttpAttestationSink(url)

    assert not [r for r in caplog.records if "plaintext" in r.message.lower()], (
        f"{url} leaks nothing and must not warn: {[r.message for r in caplog.records]}"
    )


# ---------------------------------------------------------------------------
# 3 -- the session store DSN
# ---------------------------------------------------------------------------


def _session_config(path: Path, *, dsn: str | None) -> Any:
    from nautilus.config.models import NautilusConfig

    session_store: dict[str, Any] = {"backend": "postgres", "sqlite_path": str(path / "s.db")}
    if dsn is not None:
        session_store["dsn"] = dsn
    return NautilusConfig.model_validate(
        {
            "sources": [
                {
                    "id": "orders",
                    "type": "static",
                    "description": "order rows",
                    "classification": "unclassified",
                    "data_types": ["orders"],
                    "rows": [{"order_id": 1}],
                }
            ],
            "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
            "audit": {"path": str(path / "audit.jsonl")},
            "session_store": session_store,
        }
    )


def test_e20_falling_back_to_test_pg_dsn_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The pin. Deleting session_store.dsn silently repointed the session store."""
    from nautilus.core.broker import Broker

    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    with caplog.at_level(logging.WARNING, logger="nautilus.core.broker"):
        Broker._build_session_store(_session_config(tmp_path, dsn=None), base_dir=tmp_path)

    assert any("TEST_PG_DSN" in r.message for r in caplog.records), (
        f"the fallback fired without a word: {[r.message for r in caplog.records]}"
    )


def test_e20_an_explicit_dsn_does_not_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Control. A configured deployment must not be nagged about a var it ignores."""
    from nautilus.core.broker import Broker

    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    with caplog.at_level(logging.WARNING, logger="nautilus.core.broker"):
        Broker._build_session_store(
            _session_config(tmp_path, dsn="postgres://configured/1"), base_dir=tmp_path
        )

    assert not [r for r in caplog.records if "TEST_PG_DSN" in r.message], (
        f"session_store.dsn was set explicitly: {[r.message for r in caplog.records]}"
    )
