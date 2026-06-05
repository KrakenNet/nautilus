"""Unit tests for the attestation chain-status banner on /admin/audit."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import anyio
import pytest
from fastapi import FastAPI
from fathom.attestation import AttestationService
from starlette.testclient import TestClient

from nautilus.core.attestation_sink import AttestationPayload, ChainedFileAttestationSink
from nautilus.ui.router import router

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

AUTH_HEADERS = {"X-Forwarded-User": "test-operator"}


def _build_app(broker: object) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    app.state.auth_mode = "proxy_trust"
    app.state.broker = broker
    return app


def _fake_broker(tmp_path: Path, sink: object, attestation: object) -> SimpleNamespace:
    audit_file = tmp_path / "audit.jsonl"
    audit_file.touch()
    return SimpleNamespace(
        _config=SimpleNamespace(audit=SimpleNamespace(path=str(audit_file))),
        _attestation_sink=sink,
        _attestation=attestation,
    )


def _emit_n(sink: ChainedFileAttestationSink, n: int) -> None:
    """Emit *n* payloads through the async sink from sync test code."""

    async def _run() -> None:
        for i in range(n):
            await sink.emit(
                AttestationPayload(
                    token=f"tok-{i}",
                    nautilus_payload={"i": i},
                    emitted_at=datetime.now(UTC),
                )
            )

    anyio.run(_run)


@pytest.fixture
def service() -> AttestationService:
    return AttestationService.generate_keypair()


class TestAuditChainBanner:
    def test_verified_banner_with_chained_sink(
        self, tmp_path: Path, service: AttestationService
    ) -> None:
        sink = ChainedFileAttestationSink(tmp_path / "att.jsonl", service)
        _emit_n(sink, 2)

        client = TestClient(_build_app(_fake_broker(tmp_path, sink, service)))
        resp = client.get("/admin/audit", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert "VERIFIED (2 records)" in resp.text
        assert "badge-success" in resp.text

    def test_broken_banner_on_tampered_log(
        self, tmp_path: Path, service: AttestationService
    ) -> None:
        log_path = tmp_path / "att.jsonl"
        sink = ChainedFileAttestationSink(log_path, service)
        _emit_n(sink, 3)
        lines = log_path.read_bytes().splitlines()
        del lines[1]
        log_path.write_bytes(b"\n".join(lines) + b"\n")

        client = TestClient(_build_app(_fake_broker(tmp_path, sink, service)))
        resp = client.get("/admin/audit", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert "BROKEN" in resp.text
        assert "badge-danger" in resp.text

    def test_not_chained_banner_without_chained_sink(
        self, tmp_path: Path, service: AttestationService
    ) -> None:
        client = TestClient(_build_app(_fake_broker(tmp_path, object(), service)))
        resp = client.get("/admin/audit", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert "NOT CHAINED" in resp.text

    def test_htmx_partial_skips_chain_verify(
        self, tmp_path: Path, service: AttestationService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Row-refresh requests must not re-verify the whole log."""
        import nautilus.ui.router as router_mod

        calls: list[int] = []

        def _spy(broker: object) -> None:
            calls.append(1)

        monkeypatch.setattr(router_mod, "_attestation_chain_status", _spy)
        sink = ChainedFileAttestationSink(tmp_path / "att.jsonl", service)
        client = TestClient(_build_app(_fake_broker(tmp_path, sink, service)))
        resp = client.get("/admin/audit", headers={**AUTH_HEADERS, "HX-Request": "true"})
        assert resp.status_code == 200
        assert calls == []

    def test_status_cached_until_log_changes(
        self, tmp_path: Path, service: AttestationService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Repeated page loads between appends must not re-verify the log."""
        import nautilus.ui.router as router_mod

        sink = ChainedFileAttestationSink(tmp_path / "att.jsonl", service)
        _emit_n(sink, 1)
        broker = _fake_broker(tmp_path, sink, service)

        from fathom import chained_log as chained_log_mod

        calls: list[int] = []
        original = chained_log_mod.verify_chain

        def _counting_verify(*args: object, **kwargs: object) -> object:
            calls.append(1)
            return original(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(chained_log_mod, "verify_chain", _counting_verify)

        status = cast(
            "Callable[[object], dict[str, object] | None]",
            router_mod._attestation_chain_status,  # pyright: ignore[reportPrivateUsage]
        )
        first = status(broker)
        second = status(broker)
        assert first == second
        assert len(calls) == 1

        _emit_n(sink, 1)
        third = status(broker)
        assert third is not None
        assert len(calls) == 2
