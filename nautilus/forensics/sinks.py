"""Forensic sinks for :class:`InferredHandoff` records (design §3.7, FR-11).

The offline forensic worker pipes inferred-handoff facts through a
:class:`ForensicSink` — either :class:`JSONLForensicSink` (append-only local
JSONL with ``flush`` + ``os.fsync`` per emit) or :class:`HttpForensicSink`
(best-effort POST to an external receiver).

Unlike :class:`nautilus.core.attestation_sink.HttpAttestationSink`, the HTTP
forensic sink does **not** implement retry + dead-letter spill: forensic
inference is an offline, re-runnable computation on the audit JSONL, so a
dropped POST can be replayed from source rather than queued. Failures are
logged at ``WARNING`` and swallowed — a single bad record must not crash the
worker mid-batch.

Both sinks satisfy the :class:`ForensicSink` Protocol (``@runtime_checkable``)
so operator config can select between them without the worker caring which
concrete type is in play. ``close`` is idempotent on both; calling it twice
is a no-op.
"""

from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

import httpx

from nautilus.core.models import InferredHandoff

log = logging.getLogger(__name__)


@runtime_checkable
class ForensicSink(Protocol):
    """Offline-worker sink for :class:`InferredHandoff` records.

    Implementations MUST make ``close`` idempotent; ``emit`` MUST NOT raise
    out of the worker's hot path (concrete sinks absorb their own failures
    and log at ``WARNING``).
    """

    async def emit(self, record: InferredHandoff) -> None:
        """Deliver one inferred-handoff record."""
        ...

    async def close(self) -> None:
        """Release any held resources. Must be idempotent."""
        ...


class JSONLForensicSink:
    """Append-only JSONL sink with ``flush`` + ``fsync`` per emit.

    Mirrors the durability contract of
    :class:`nautilus.core.attestation_sink.FileAttestationSink`: each
    :meth:`emit` is one ``write`` + ``flush`` + ``os.fsync`` syscall trio so
    a crash between two emits can only lose at most zero entries before the
    crashing emit. Writes are NOT batched; the offline worker is not on the
    broker hot path so the per-emit fsync cost is acceptable.

    ``close`` is idempotent; subsequent :meth:`emit` calls after
    :meth:`close` raise :class:`ValueError` (propagated from the closed
    handle). Callers that need resume-after-close must construct a fresh
    sink.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        # Parent-dir creation matches FileAttestationSink so consumers can
        # point at fresh ``tempfile.mkstemp`` locations or operator-provisioned
        # mount points without a pre-create step.
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self._path.open("a", encoding="utf-8")
        self._closed = False

    async def emit(self, record: InferredHandoff) -> None:
        """Write one JSONL line + ``flush`` + ``os.fsync``."""
        line = record.model_dump_json() + "\n"
        self._fh.write(line)
        self._fh.flush()
        os.fsync(self._fh.fileno())

    async def close(self) -> None:
        """Idempotent close: close the handle iff still open."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            self._fh.close()


class HttpForensicSink:
    """HTTP POST sink for inferred handoffs (offline, no retry/dead-letter).

    Each :meth:`emit` POSTs ``record.model_dump(mode="json")`` to ``url`` via a
    shared :class:`httpx.AsyncClient`. Transient failures
    (:class:`httpx.TransportError`, :class:`httpx.TimeoutException`, or a
    non-2xx status) are logged at ``WARNING`` and swallowed — the offline
    forensic worker is re-runnable from the audit JSONL, so a dropped POST
    can be replayed from source rather than queued.

    :meth:`close` is idempotent and awaits :meth:`httpx.AsyncClient.aclose`.
    """

    def __init__(self, url: str) -> None:
        self._url = url
        # ``httpx.AsyncClient`` defers the actual connection until first
        # request; construction is cheap and the smoke-test in the Verify
        # command never touches the network.
        self._client = httpx.AsyncClient()
        self._closed = False

    async def emit(self, record: InferredHandoff) -> None:
        """POST ``record`` to ``url``; log + swallow any failure."""
        body = record.model_dump(mode="json")
        try:
            response = await self._client.post(self._url, json=body)
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            log.warning(
                "forensic_sink.http emit failed: %s: %s; url=%s",
                type(exc).__name__,
                exc,
                self._url,
            )
            return
        status = response.status_code
        if status >= 400:
            log.warning(
                "forensic_sink.http emit got HTTP %d; url=%s",
                status,
                self._url,
            )

    async def close(self) -> None:
        """Idempotent close: aclose the httpx client."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            await self._client.aclose()


__all__ = [
    "ForensicSink",
    "HttpForensicSink",
    "JSONLForensicSink",
]
