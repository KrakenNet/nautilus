"""``AttestationSink`` Protocol and Phase-1/2 implementations (design §3.14, D-18).

Durable store-and-forward delivery of signed attestation payloads. Parallels
the Phase-1 :class:`nautilus.audit.sinks.AuditSink` Protocol but is kept as a
*separate* Protocol per D-18 — attestation has a different lifecycle (may
retry, may fail, may dead-letter) from audit (immutable local record, always
succeeds). Sharing a Protocol would force dual-purpose implementations.

Task 1.13 lands the Protocol, :class:`AttestationPayload` model, and the two
Phase-1-selectable sinks:

- :class:`NullAttestationSink` — the default; no-op ``emit``/``close``. Used
  when ``config.attestation.sink.type == "null"`` (or the subsection is
  omitted, preserving NFR-5 backwards compat).
- :class:`FileAttestationSink` — append-only JSONL with ``flush()`` +
  ``os.fsync(fd)`` per ``emit`` (AC-14.2, durable-before-ack).

:class:`HttpAttestationSink` (design §3.14, AC-14.3) POSTs each payload to a
verifier endpoint with an exponential-backoff retry schedule and, on exhausted
retries, dead-letters the payload to a wrapped :class:`FileAttestationSink`.

**Audit-first invariant (AC-14.5 / NFR-16).** An exception raised from any
sink's ``emit`` MUST NOT abort :meth:`nautilus.core.broker.Broker.arequest`.
The broker wraps each emit in ``try/except Exception`` and logs at WARNING;
the audit entry is still written and the response still returned.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel, ConfigDict

log = logging.getLogger(__name__)


class AttestationPayload(BaseModel):
    """Store-and-forward envelope for a single attestation emission.

    - ``token`` — the signed Fathom JWT (design §9.3).
    - ``nautilus_payload`` — the Nautilus claim set that was signed (mirrors
      :func:`nautilus.core.attestation_payload.build_payload` output).
    - ``emitted_at`` — broker-local timestamp at emit time; sinks may rewrite
      this on retry but the broker records the original attempt.
    """

    model_config = ConfigDict(extra="forbid")

    token: str
    nautilus_payload: dict[str, Any]
    emitted_at: datetime


@runtime_checkable
class AttestationSink(Protocol):
    """Store-and-forward target for signed attestation payloads.

    Implementations MUST be safe to call ``close`` multiple times (idempotent);
    in-flight ``emit`` calls after ``close`` should raise or no-op per the
    concrete sink's contract.
    """

    async def emit(self, payload: AttestationPayload) -> None:
        """Deliver one payload. May raise — broker wraps in try/except."""
        ...

    async def close(self) -> None:
        """Release any held resources. Must be idempotent."""
        ...


class NullAttestationSink:
    """Default sink: no-op ``emit`` and ``close``.

    Selected when ``config.attestation.sink.type == "null"`` (or the sink
    subsection is absent in a Phase-1 YAML fixture, preserving NFR-5
    backwards compatibility). The attestation token is still signed and
    returned on :attr:`nautilus.core.models.BrokerResponse.attestation_token`
    (AC-14.4) — the null sink only skips the store-and-forward step.
    """

    async def emit(self, payload: AttestationPayload) -> None:  # noqa: ARG002
        """No-op."""
        return None

    async def close(self) -> None:
        """No-op."""
        return None


class FileAttestationSink:
    """Append-only JSONL sink with ``flush`` + ``fsync`` per emit (AC-14.2).

    Opens ``path`` in text append mode at construction time so each
    :meth:`emit` is one ``write`` + ``flush`` + ``os.fsync`` syscall trio —
    durable-before-ack semantics (NFR-16). Writes are NOT batched; each
    emit is independently fsynced so a crash between two emits can only
    lose at most zero entries before the crashing emit.

    ``close`` is idempotent; subsequent ``emit`` calls after ``close``
    raise :class:`ValueError` (propagated from the closed handle). The
    broker's ``_emit_attestation`` wrapper swallows that exception per
    AC-14.5 so this failure mode never breaks the hot path.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        # Ensure parent directory exists so consumers can point at fresh
        # ``tempfile.mkstemp`` locations (as the Verify command does) or at
        # operator-provisioned mount points (``/audit/attestation.jsonl``).
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Text-mode append; line-buffering irrelevant because every emit
        # manually flushes + fsyncs. ``utf-8`` is explicit so Windows hosts
        # (which default to cp1252) don't silently mangle JSON.
        self._fh = self._path.open("a", encoding="utf-8")
        self._closed = False

    async def emit(self, payload: AttestationPayload) -> None:
        """Write one JSONL line + ``flush`` + ``os.fsync`` (AC-14.2)."""
        line = payload.model_dump_json() + "\n"
        self._fh.write(line)
        self._fh.flush()
        os.fsync(self._fh.fileno())

    async def close(self) -> None:
        """Idempotent close: close the handle iff still open."""
        if self._closed:
            return
        self._closed = True
        # Best-effort close per D-8; a failing underlying handle must not
        # propagate since aclose ordering requires sink.close() succeed for
        # the adapter release step to proceed.
        with contextlib.suppress(Exception):
            self._fh.close()


class RetryPolicy(BaseModel):
    """Exponential-backoff retry schedule for :class:`HttpAttestationSink`.

    - ``max_retries`` counts *additional* attempts after the initial POST; the
      total number of POSTs is ``max_retries + 1``. ``max_retries=0`` means
      exactly one attempt and, on failure, straight to dead-letter.
    - Backoff for retry attempt ``n`` (0-indexed over retries) is
      ``min(initial_backoff_s * 2**n, max_backoff_s)``; the cap prevents
      pathological multi-minute sleeps when ``max_retries`` is large.
    """

    model_config = ConfigDict(extra="forbid")

    max_retries: int = 3
    initial_backoff_s: float = 0.1
    max_backoff_s: float = 5.0


class HttpAttestationSink:
    """HTTP POST sink with retry + dead-letter spill (design §3.14, AC-14.3).

    Each :meth:`emit` POSTs ``payload.model_dump(mode="json")`` to ``url`` via a
    shared :class:`httpx.AsyncClient`. On transient failure (``httpx.TransportError``,
    ``httpx.TimeoutException``, or a ``5xx`` status) the sink retries with
    exponential backoff per :class:`RetryPolicy`; on ``4xx`` status the error
    is permanent (client fault) and retries are skipped. When all attempts are
    exhausted a single WARN is logged and — if ``dead_letter_path`` was set —
    the payload is handed to a wrapped :class:`FileAttestationSink` for
    durable spill (NFR-16). If ``dead_letter_path`` is ``None`` the WARN is
    the only side effect.

    :meth:`close` is idempotent and awaits both :meth:`httpx.AsyncClient.aclose`
    and the wrapped dead-letter sink's ``close`` (if any). The sink never
    raises out of :meth:`emit`; the broker's :meth:`_emit_attestation` still
    wraps it in try/except per AC-14.5 but this class absorbs its own failure
    modes so the audit-first invariant holds even if the broker wrapper is
    later tightened.
    """

    def __init__(
        self,
        url: str,
        *,
        retry_policy: RetryPolicy | None = None,
        dead_letter_path: Path | str | None = None,
    ) -> None:
        self._url = url
        self._retry_policy = retry_policy if retry_policy is not None else RetryPolicy()
        # ``httpx.AsyncClient`` defers the actual connection until first
        # request, so construction is cheap and the smoke-test in the Verify
        # command never touches the network.
        self._client = httpx.AsyncClient()
        self._dead_letter: FileAttestationSink | None = (
            FileAttestationSink(dead_letter_path) if dead_letter_path is not None else None
        )
        self._closed = False

    def _backoff_for(self, attempt: int) -> float:
        """Compute capped exponential backoff for retry index ``attempt``."""
        policy = self._retry_policy
        return min(policy.initial_backoff_s * (2**attempt), policy.max_backoff_s)

    async def emit(self, payload: AttestationPayload) -> None:
        """POST ``payload`` with retry; dead-letter on exhaustion.

        Retries :class:`httpx.TransportError`, :class:`httpx.TimeoutException`,
        and ``5xx`` responses. ``4xx`` responses short-circuit to the
        dead-letter path — the client is wrong; retrying won't fix it.
        """
        body = payload.model_dump(mode="json")
        policy = self._retry_policy
        total_attempts = policy.max_retries + 1
        last_error: str = "unknown"
        for attempt in range(total_attempts):
            try:
                response = await self._client.post(self._url, json=body)
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                status = response.status_code
                if 200 <= status < 300:
                    return
                if 400 <= status < 500:
                    # Permanent client error; no retry, straight to dead-letter.
                    last_error = f"HTTP {status} (client error, no retry)"
                    break
                # 5xx (or other) — retriable.
                last_error = f"HTTP {status}"
            # Sleep only if a further retry is still scheduled.
            if attempt < total_attempts - 1:
                await asyncio.sleep(self._backoff_for(attempt))
        # All attempts exhausted — spill and warn.
        log.warning(
            "attestation_sink.http emit failed after %d attempt(s): %s; url=%s",
            total_attempts,
            last_error,
            self._url,
        )
        if self._dead_letter is not None:
            # Dead-letter write itself must not raise out of emit; the
            # FileAttestationSink already fsyncs per line (AC-14.2).
            with contextlib.suppress(Exception):
                await self._dead_letter.emit(payload)

    async def close(self) -> None:
        """Idempotent close: aclose the httpx client + dead-letter sink."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            await self._client.aclose()
        if self._dead_letter is not None:
            with contextlib.suppress(Exception):
                await self._dead_letter.close()


__all__ = [
    "AttestationPayload",
    "AttestationSink",
    "FileAttestationSink",
    "HttpAttestationSink",
    "NullAttestationSink",
    "RetryPolicy",
]
