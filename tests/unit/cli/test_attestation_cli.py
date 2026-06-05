"""Unit tests for ``nautilus attestation verify`` (offline chain verification)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from fathom.attestation import AttestationService
from fathom.chained_log import ChainedAttestationLog

from nautilus.cli import main

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def chained_log(tmp_path: Path) -> Path:
    service = AttestationService.generate_keypair()
    log = ChainedAttestationLog(tmp_path / "att.jsonl", service)
    for i in range(3):
        log.append({"token": f"tok-{i}", "nautilus_payload": {"i": i}})
    log.close()
    return log.path


class TestAttestationVerify:
    def test_valid_chain_exits_0(
        self, chained_log: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["attestation", "verify", str(chained_log)])
        assert rc == 0
        assert "OK: chain valid" in capsys.readouterr().out

    def test_json_output(self, chained_log: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["attestation", "verify", str(chained_log), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["ok"] is True
        assert data["count"] == 3

    def test_tampered_chain_exits_2(
        self, chained_log: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        lines = chained_log.read_bytes().splitlines()
        del lines[1]
        chained_log.write_bytes(b"\n".join(lines) + b"\n")
        rc = main(["attestation", "verify", str(chained_log)])
        assert rc == 2
        assert "ERROR" in capsys.readouterr().err

    def test_truncation_detected_with_expected_head(
        self, chained_log: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["attestation", "verify", str(chained_log), "--json"])
        assert rc == 0
        head = json.loads(capsys.readouterr().out)["head_sha256"]

        lines = chained_log.read_bytes().splitlines()
        chained_log.write_bytes(b"\n".join(lines[:1]) + b"\n")
        rc = main(["attestation", "verify", str(chained_log), "--expected-head", head])
        assert rc == 2
        assert "truncated" in capsys.readouterr().err

    def test_missing_log_exits_1(self, tmp_path: Path) -> None:
        rc = main(["attestation", "verify", str(tmp_path / "missing.jsonl")])
        assert rc == 1

    def test_missing_pubkey_exits_1(self, chained_log: Path) -> None:
        chained_log.with_name("att.jsonl.pub.pem").unlink()
        rc = main(["attestation", "verify", str(chained_log)])
        assert rc == 1
