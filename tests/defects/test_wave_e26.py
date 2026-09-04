"""WAVE E26 -- ``schema-ack`` met the audit writer lock with a traceback.

With ``audit.chained: true`` and a server running, acknowledging schema drift
crashed::

    nautilus.core.attestation_sink.SinkAlreadyLockedError: chained audit log
    audit.jsonl is already open for writing by pid 2858986. ...

Exit 1, raw traceback. The crash came from ``broker.emit_adapter_event`` -- the
*second* half of the command. The first half, ``fingerprint_store.record_ack``,
had already rewritten the baseline on disk with the reviewer and the reason, so
the drift was accepted and the log that exists to say who accepted it never got
the line. That is the failure ``nautilus/cli/_common.py`` already refuses for a
governance decision, one probe earlier, with exit 2 and a sentence.

The pins run the real CLI in a real process against a real chained log whose
lock a real second process holds, because the bug only exists across processes:
``flock`` is per-process, and a same-process second handle takes it happily.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

# Holds the audit writer lock the way a serving broker holds it: by emitting an
# adapter event through the configured sink, not by locking the file by hand.
_HOLDER = """
import sys, time
from nautilus.core.broker import Broker
broker = Broker.from_config(sys.argv[1])
broker.emit_adapter_event("adapter_quarantined", "orders")
print("locked", flush=True)
time.sleep(120)
"""


def _config(tmp_path: Path) -> Path:
    """A loadable ``nautilus.yaml`` with a chained audit log and one adapter.

    The signing key is on disk: a chained log signed by an auto-generated key
    cannot be appended to by the next process, and this test needs two.
    """
    from fathom.chained_log import load_or_create_key

    key_path = tmp_path / "attestation-key.pem"
    load_or_create_key(key_path)
    config: dict[str, Any] = {
        "sources": [
            {
                "id": "orders",
                "type": "static",
                "description": "declared rows, so get_schema answers without I/O",
                "classification": "unclassified",
                "data_types": ["orders"],
                "allowed_purposes": ["care"],
                "rows": [{"order_id": 1, "total": 2.0}],
            }
        ],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl"), "chained": True},
        "attestation": {"enabled": True, "private_key_path": str(key_path)},
        "rules": {"packs": [], "user_rules_dirs": []},
        "api": {"keys": ["k"]},
        "state_dir": str(tmp_path / "state"),
    }
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


def _baseline(tmp_path: Path) -> Path:
    return tmp_path / "state" / ".nautilus" / "adapters" / "fingerprints" / "orders.json"


def _schema_ack(config: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "nautilus",
            "adapters",
            "schema-ack",
            "orders",
            "--config",
            str(config),
            "--reason",
            "upstream added a nullable column",
            "--yes",
        ],
        capture_output=True,
        text=True,
        env={"NAUTILUS_REVIEWER": "ops@example.com", "PATH": "/usr/bin:/bin"},
        timeout=120,
    )


def _writer(config: Path) -> subprocess.Popen[str]:
    """A second process holding the chained log's writer lock."""
    holder = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, str(config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert holder.stdout is not None
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        line = holder.stdout.readline()
        if line.strip() == "locked":
            return holder
        if not line and holder.poll() is not None:
            break
    holder.kill()
    stderr = holder.stderr.read() if holder.stderr else ""
    pytest.fail(f"the lock holder never claimed the audit log: {stderr}")


def test_e26_schema_ack_refuses_a_locked_audit_log_instead_of_crashing(tmp_path: Path) -> None:
    """Exit 2 and a sentence, the way a refused governance decision reads."""
    config = _config(tmp_path)
    holder = _writer(config)
    try:
        result = _schema_ack(config)
    finally:
        holder.kill()
        holder.wait(timeout=30)

    assert "Traceback" not in result.stderr, (
        f"schema-ack handed the operator a traceback:\n{result.stderr}"
    )
    assert result.returncode == 2, (
        f"expected exit 2 (the code every other command uses for this lock), got "
        f"{result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert result.stderr.startswith("ERROR: this acknowledgement cannot be recorded"), result.stderr
    # The refusal has to carry the same three parts as the governance one:
    # what will not happen, why, and what to do instead.
    assert "another process is writing the chained audit log" in result.stderr
    assert "Stop the server first" in result.stderr
    assert "is already open for writing by pid" in result.stderr


def test_e26_a_refused_ack_leaves_the_baseline_alone(tmp_path: Path) -> None:
    """Nothing is acknowledged when the acknowledgement cannot be recorded.

    The crash landed *after* ``record_ack``, so the drift was accepted on disk
    -- reviewer, reason and all -- and the audit log said nothing about it. A
    later ``schema-diff`` then reported no drift, and the record of who accepted
    it did not exist.
    """
    config = _config(tmp_path)
    holder = _writer(config)
    try:
        result = _schema_ack(config)
    finally:
        holder.kill()
        holder.wait(timeout=30)

    assert result.returncode == 2, result.stderr
    assert not _baseline(tmp_path).exists(), (
        f"the refused ack still rewrote the baseline: "
        f"{_baseline(tmp_path).read_text(encoding='utf-8')}"
    )


def test_e26_schema_ack_still_records_into_a_chained_log(tmp_path: Path) -> None:
    """With the lock free, the probe takes it and the ack goes through.

    The probe acquires rather than peeks, so this is the path that would break
    if refusing were done by locking and then failing to hold the lock through
    the write: the baseline is written, the override is audited, and the chain
    still verifies offline against the key beside it.
    """
    from fathom.attestation import AttestationService
    from fathom.chained_log import verify_chain

    config = _config(tmp_path)
    result = _schema_ack(config)

    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
    assert result.stdout.startswith("OK: schema-ack recorded for 'orders'")
    recorded = json.loads(_baseline(tmp_path).read_text(encoding="utf-8"))
    assert recorded["reviewer"] == "ops@example.com"

    audit_path = tmp_path / "audit.jsonl"
    # Line 0 of a chained log is its genesis header, which carries no record.
    records = [json.loads(line)["record"] for line in audit_path.read_text("utf-8").splitlines()]
    entries = [
        json.loads(r["metadata"]["nautilus_audit_entry"]) for r in records if "metadata" in r
    ]
    assert [e["event_type"] for e in entries] == ["schema_drift_severity_overridden"], entries
    assert entries[0]["adapter_id"] == "orders"

    service = AttestationService.from_private_key_bytes(
        (tmp_path / "attestation-key.pem").read_bytes()
    )
    verification = verify_chain(audit_path, service.public_key_pem())
    assert verification.ok, verification.error
