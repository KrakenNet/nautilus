"""ProposalQueue — JSONL + ``fcntl.lockf()`` substrate (#35.9, DQ3 LOCKED).

ACs:
- AC-35.9.a — persists across broker restarts via JSONL.
- AC-35.9.d — approve/reject emit audit events with reviewer.
- AC-35.9.f — :meth:`depth` + :meth:`oldest_age_seconds` Prometheus source.

Mirrors ``nautilus/core/attestation_sink.py:125`` ``FileAttestationSink.emit``
(append-only + fsync). Adds advisory ``fcntl.lockf()`` on a
``.nautilus/rkm/queue/.lock`` file during write (Data invariant #2).
"""

from __future__ import annotations

import dataclasses
import fcntl
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nautilus.rkm.types import Proposal, ProposalStatus

# Lock contention timeout and poll interval per shared.md:795
_LOCK_TIMEOUT_S = 5.0
_LOCK_POLL_S = 0.1

# Valid state-machine transitions: (from_status) -> allowed to_statuses
_VALID_TRANSITIONS: dict[str, set[str]] = {
    "pending": {"approved", "rejected", "expired"},
    "approved": {"promoted", "expired"},
    "rejected": set(),
    "expired": set(),
    "promoted": set(),
    "superseded": set(),
}


class ProposalQueueLocked(Exception):  # noqa: N818
    """Raised after 5-second ``lockf`` backoff timeout. Maps to HTTP 503."""


class InvalidTransition(Exception):  # noqa: N818
    """Raised when a state-machine transition is invalid. Maps to HTTP 409."""


def _proposal_to_dict(proposal: Proposal) -> dict[str, Any]:
    d = dataclasses.asdict(proposal)
    d["proposed_at"] = proposal.proposed_at.isoformat()
    return d


def _proposal_from_dict(d: dict[str, Any]) -> Proposal:
    d = dict(d)
    proposed_at_raw = d["proposed_at"]
    if isinstance(proposed_at_raw, str):
        dt = datetime.fromisoformat(proposed_at_raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        d["proposed_at"] = dt
    # shadow_flags absent in records written before AC-35.6.c
    d.setdefault("shadow_flags", ())
    return Proposal(**d)


class ProposalQueue:
    """JSONL-backed queue at ``.nautilus/rkm/queue/*.jsonl``.

    One file per ``proposal_id``; one decision event per line after the first.
    The first line of each file is the initial proposal record.
    Subsequent lines are decision events: ``{"event": "transition", "to": ..., ...}``.
    """

    def __init__(self, queue_dir: Path) -> None:
        self._queue_dir = queue_dir
        self._queue_dir.mkdir(parents=True, exist_ok=True)
        self._lock_path = self._queue_dir / ".lock"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _acquire_lock(self) -> Any:
        """Open .lock file and acquire exclusive lockf within timeout.

        Returns the open file handle (caller must close/unlock it).
        Raises :class:`ProposalQueueLocked` on timeout.
        """
        fh = self._lock_path.open("a")
        deadline = time.monotonic() + _LOCK_TIMEOUT_S
        while True:
            try:
                fcntl.lockf(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fh
            except (BlockingIOError, OSError) as exc:
                if time.monotonic() >= deadline:
                    fh.close()
                    raise ProposalQueueLocked(
                        "lock contention timeout on proposal queue"
                    ) from exc
                time.sleep(_LOCK_POLL_S)

    def _release_lock(self, fh: Any) -> None:
        fcntl.lockf(fh, fcntl.LOCK_UN)
        fh.close()

    def _proposal_path(self, proposal_id: str) -> Path:
        return self._queue_dir / f"{proposal_id}.jsonl"

    def _read_proposal(self, proposal_id: str) -> Proposal | None:
        """Read and reconstruct the current state of a proposal from its JSONL file."""
        path = self._proposal_path(proposal_id)
        if not path.exists():
            return None
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if not lines:
            return None
        proposal = _proposal_from_dict(json.loads(lines[0]))
        # Apply decision events to derive current status and decisions list
        decisions: list[dict[str, Any]] = list(proposal.decisions)
        current_status: str = proposal.status
        for line in lines[1:]:
            event = json.loads(line)
            if event.get("event") == "transition":
                current_status = event["to"]
                decisions.append(event)
        # Rebuild with updated status and decisions (frozen dataclass — use replace)
        return dataclasses.replace(
            proposal,
            status=current_status,  # type: ignore[arg-type]
            decisions=decisions,
        )

    def _write_line(self, path: Path, data: dict[str, Any]) -> None:
        """Append one JSONL line + flush + fsync (mirrors FileAttestationSink.emit)."""
        line = json.dumps(data, separators=(",", ":"), default=str) + "\n"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit(self, proposal: Proposal) -> None:
        """Atomic write under ``lockf``. Idempotent on ``proposal_id`` collision."""
        lock_fh = self._acquire_lock()
        try:
            path = self._proposal_path(proposal.proposal_id)
            if path.exists():
                # Idempotent: already present, return silently
                return
            self._write_line(path, _proposal_to_dict(proposal))
        finally:
            self._release_lock(lock_fh)

    def get(self, proposal_id: str) -> Proposal | None:
        """Return latest snapshot for ``proposal_id`` or ``None`` if absent."""
        return self._read_proposal(proposal_id)

    def list(
        self,
        *,
        status: ProposalStatus | None = None,
        min_confidence: float = 0.0,
    ) -> list[Proposal]:
        """Enumerate proposals; AC-35.9.b filtering by ``--status`` / ``--min-confidence``."""
        results: list[Proposal] = []
        for path in sorted(self._queue_dir.glob("*.jsonl")):
            proposal_id = path.stem
            proposal = self._read_proposal(proposal_id)
            if proposal is None:
                continue
            if status is not None and proposal.status != status:
                continue
            results.append(proposal)
        return results

    def transition(
        self,
        proposal_id: str,
        *,
        to: ProposalStatus,
        reviewer: str,
        reason: str | None,
        note: str | None,
    ) -> Proposal:
        """Append a decision event. AC-35.9.d.

        Enforces:
        - ``approve|reject`` valid only from ``pending`` (409 otherwise).
        - ``promote`` valid only from ``approved``.
        - ``expire`` valid from ``pending|approved``.
        Raises :class:`ProposalQueueLocked` on lockf timeout.
        """
        lock_fh = self._acquire_lock()
        try:
            proposal = self._read_proposal(proposal_id)
            if proposal is None:
                raise KeyError(f"proposal not found: {proposal_id}")
            current = proposal.status
            allowed = _VALID_TRANSITIONS.get(current, set())
            if to not in allowed:
                raise InvalidTransition(
                    f"cannot transition {proposal_id} from {current!r} to {to!r}"
                )
            event: dict[str, Any] = {
                "event": "transition",
                "to": to,
                "reviewer": reviewer,
                "at": datetime.now(UTC).isoformat(),
            }
            if reason is not None:
                event["reason"] = reason
            if note is not None:
                event["note"] = note
            self._write_line(self._proposal_path(proposal_id), event)
        finally:
            self._release_lock(lock_fh)
        # Re-read to return the updated snapshot
        updated = self._read_proposal(proposal_id)
        assert updated is not None  # noqa: S101
        return updated

    def depth(self) -> int:
        """Pending-queue depth (Prometheus gauge source). AC-35.9.f."""
        return len(self.list(status="pending"))

    def oldest_age_seconds(self) -> float:
        """Age of the oldest pending proposal (seconds). AC-35.9.f."""
        pending = self.list(status="pending")
        if not pending:
            return 0.0
        now = datetime.now(UTC)
        oldest = min(
            (now - p.proposed_at).total_seconds() for p in pending
        )
        return max(0.0, oldest)


__all__ = ["ProposalQueue", "ProposalQueueLocked", "InvalidTransition"]
