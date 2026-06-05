"""Unit tests for :class:`ChainedFileAttestationSink` (FileSinkSpec ``chained: true``)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from fathom.attestation import AttestationService
from fathom.chained_log import verify_chain
from fathom.errors import AttestationError

from nautilus.config.models import AttestationConfig, FileSinkSpec
from nautilus.core.attestation_sink import AttestationPayload, ChainedFileAttestationSink
from nautilus.core.broker import Broker

if TYPE_CHECKING:
    from pathlib import Path


def _payload(i: int = 0) -> AttestationPayload:
    return AttestationPayload(
        token=f"tok-{i}",
        nautilus_payload={"decision": f"allow-{i}"},
        emitted_at=datetime.now(UTC),
    )


@pytest.fixture
def service() -> AttestationService:
    return AttestationService.generate_keypair()


class TestChainedFileAttestationSink:
    async def test_emit_chains_and_verifies(
        self, tmp_path: Path, service: AttestationService
    ) -> None:
        log_path = tmp_path / "att.jsonl"
        sink = ChainedFileAttestationSink(log_path, service)
        for i in range(3):
            await sink.emit(_payload(i))
        await sink.close()

        result = verify_chain(log_path, service.public_key)
        assert result.ok
        assert result.count == 3

    async def test_public_key_exported_beside_log(
        self, tmp_path: Path, service: AttestationService
    ) -> None:
        log_path = tmp_path / "att.jsonl"
        ChainedFileAttestationSink(log_path, service)
        assert (tmp_path / "att.jsonl.pub.pem").read_bytes() == service.public_key_pem()

    async def test_reopen_resumes_chain(self, tmp_path: Path, service: AttestationService) -> None:
        log_path = tmp_path / "att.jsonl"
        sink1 = ChainedFileAttestationSink(log_path, service)
        await sink1.emit(_payload(0))
        await sink1.close()

        sink2 = ChainedFileAttestationSink(log_path, service)
        await sink2.emit(_payload(1))
        await sink2.close()

        result = verify_chain(log_path, service.public_key)
        assert result.ok
        assert result.count == 2

    async def test_corrupt_log_fails_closed(
        self, tmp_path: Path, service: AttestationService
    ) -> None:
        log_path = tmp_path / "att.jsonl"
        sink = ChainedFileAttestationSink(log_path, service)
        await sink.emit(_payload(0))
        await sink.close()
        log_path.write_bytes(log_path.read_bytes() + b'{"torn"')

        reopened = ChainedFileAttestationSink(log_path, service)
        with pytest.raises(AttestationError, match="refusing append"):
            await reopened.emit(_payload(1))

    async def test_emit_after_close_raises(
        self, tmp_path: Path, service: AttestationService
    ) -> None:
        sink = ChainedFileAttestationSink(tmp_path / "att.jsonl", service)
        await sink.close()
        await sink.close()  # idempotent
        with pytest.raises(ValueError, match="closed"):
            await sink.emit(_payload())


class TestBrokerSinkWiring:
    def _config(self, tmp_path: Path, *, chained: bool) -> AttestationConfig:
        return AttestationConfig(
            sink=FileSinkSpec(path=str(tmp_path / "att.jsonl"), chained=chained)
        )

    def test_chained_spec_builds_chained_sink(self, tmp_path: Path) -> None:
        from nautilus.config.models import NautilusConfig

        config = NautilusConfig.model_construct(attestation=self._config(tmp_path, chained=True))
        service = AttestationService.generate_keypair()
        sink = Broker._build_attestation_sink(config, service)
        assert isinstance(sink, ChainedFileAttestationSink)

    def test_chained_spec_without_attestation_raises(self, tmp_path: Path) -> None:
        from nautilus.config.models import NautilusConfig

        config = NautilusConfig.model_construct(attestation=self._config(tmp_path, chained=True))
        with pytest.raises(ValueError, match="requires attestation.enabled"):
            Broker._build_attestation_sink(config, None)

    def test_unchained_spec_unaffected(self, tmp_path: Path) -> None:
        from nautilus.config.models import NautilusConfig
        from nautilus.core.attestation_sink import FileAttestationSink

        config = NautilusConfig.model_construct(attestation=self._config(tmp_path, chained=False))
        sink = Broker._build_attestation_sink(config, None)
        assert isinstance(sink, FileAttestationSink)
