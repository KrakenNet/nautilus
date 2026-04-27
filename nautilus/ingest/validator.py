"""JSON-Schema validation for ingested rows (US-4, Tasks 26 + 30).

The :class:`SchemaValidator` compiles a ``Draft202012Validator`` once at
``adapter.connect()`` time and then partitions each batch of rows into
``(ok_rows, violations)`` where each violation pairs the offending row
with a human-readable reason string.

The :func:`_validate_ingest_integrity` function is the orchestrator entry
point that :class:`~nautilus.adapters.rest.RestAdapter` calls after
``_coerce_rows()``. It runs four ordered steps (design.md §723-759):

1. Publisher schema-change check (may raise :class:`IngestPausedError`
   when ``on_publisher_schema_change="pause"``).
2. Per-row JSON-schema validation; violations are routed per
   ``on_schema_violation`` (``quarantine`` / ``reject`` / ``pass-through``).
3. Baseline update + anomaly check — anomalies emit an audit entry but
   never block the batch (operators act on the metric counter).
4. Optional user-supplied ``corroboration_callback`` applied to ``ok_rows``.

Design reference: Component Responsibilities → ``SchemaValidator``
(design.md §710-768). FR-13, FR-20, AC-4.1, AC-4.4, AC-4.5, AC-4.11.
"""

from __future__ import annotations

import inspect
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as _JSValidationError

from nautilus.core.models import AuditEntry
from nautilus.ingest.errors import SchemaViolationError

if TYPE_CHECKING:
    from nautilus.audit.logger import AuditLogger
    from nautilus.config.secrets import SecretProvider
    from nautilus.ingest.baseline import BaselineTracker
    from nautilus.ingest.config import IngestIntegrityConfig
    from nautilus.ingest.quarantine import QuarantineSink
    from nautilus.ingest.schema_change import SchemaChangeDetector

_LOG = logging.getLogger(__name__)

__all__ = [
    "IngestValidators",
    "SchemaValidator",
    "_validate_ingest_integrity",
]


class SchemaValidator:
    """Compile-once JSON-Schema validator for a single source.

    Parameters
    ----------
    schema_ref:
        Either a filesystem path (``/etc/nautilus/schemas/n.json``) or a
        secret reference (``env://VAR``, ``vault://kv/...``). The value is
        copied from :attr:`IngestIntegrityConfig.schema_`.
    resolver:
        Optional :class:`~nautilus.config.secrets.SecretProvider` used to
        dereference a ``<scheme>://`` ref. Required iff ``schema_ref``
        contains ``"://"``.
    """

    def __init__(
        self,
        schema_ref: str,
        *,
        resolver: SecretProvider | None = None,
    ) -> None:
        self._schema_ref = schema_ref
        self._resolver = resolver
        self._validator: Draft202012Validator | None = None

    async def compile(self) -> None:
        """Load + compile the JSON-Schema document. Idempotent (cached)."""
        if self._validator is not None:
            return

        raw = await self._load_schema_document()
        schema: dict[str, Any] = json.loads(raw) if isinstance(raw, str) else raw
        # ``check_schema`` raises ``jsonschema.SchemaError`` on a malformed
        # schema; we let that propagate so misconfiguration fails fast at
        # adapter ``connect()`` time.
        Draft202012Validator.check_schema(schema)
        self._validator = Draft202012Validator(schema)

    async def _load_schema_document(self) -> str | dict[str, Any]:
        """Return either raw JSON text (from disk / secret) or a parsed dict."""
        if "://" in self._schema_ref:
            if self._resolver is None:
                raise ValueError(
                    "SchemaValidator: schema ref has a scheme but no resolver was supplied"
                )
            return await self._resolver.get(self._schema_ref)
        # Bare filesystem path — schema files are small (<1 MB) and this is
        # called once per adapter lifetime. ``ASYNC240`` fires on
        # ``Path.read_text`` in async fns, but the single-shot call at
        # ``connect()`` time is not a hot-path concern. Noqa-localised.
        return Path(self._schema_ref).read_text(encoding="utf-8")  # noqa: ASYNC240

    def validate(
        self,
        rows: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[tuple[dict[str, Any], str]]]:
        """Partition ``rows`` into ``(ok_rows, violations)``.

        Each violation is a ``(row, reason)`` pair where ``reason`` is a
        human-readable string built from the first :class:`jsonschema.ValidationError`
        surfaced by ``iter_errors`` on that row.
        """
        if self._validator is None:
            raise RuntimeError("SchemaValidator.validate() called before compile()")

        ok: list[dict[str, Any]] = []
        violations: list[tuple[dict[str, Any], str]] = []
        for row in rows:
            # jsonschema's ``iter_errors`` overload signature is partially
            # unknown to pyright; cast the returned generator's items to the
            # concrete ``ValidationError`` type we actually consume.
            raw_errors = self._validator.iter_errors(row)  # pyright: ignore[reportUnknownMemberType]
            errors: list[_JSValidationError] = list(raw_errors)
            if errors:
                violations.append((row, _format_reason(errors[0])))
            else:
                ok.append(row)
        return ok, violations


def _format_reason(err: _JSValidationError) -> str:
    """Render a :class:`jsonschema.ValidationError` as a compact reason string.

    Format: ``"<json_path>: <message>"`` — e.g. ``"$.age: -1 is less than the
    minimum of 0"``. When the error is at the document root, the path is just
    ``"$"``.
    """
    path = "$"
    if err.absolute_path:
        parts = [f"[{p!r}]" if isinstance(p, int) else f".{p}" for p in err.absolute_path]
        path = "$" + "".join(parts)
    return f"{path}: {err.message}"


@dataclass
class IngestValidators:
    """Precompiled validator bundle passed to :func:`_validate_ingest_integrity`.

    Built once at :meth:`~nautilus.adapters.rest.RestAdapter.connect` time
    and re-used across every ``execute()``. Any slot may be ``None`` when
    the corresponding feature is not configured for this source (e.g. a
    source with no ``baseline_window`` still gets schema validation + the
    schema-change gate); the orchestrator branches ``if obj is not None``
    on each slot so unconfigured features cost zero runtime overhead.
    """

    schema_validator: SchemaValidator
    baseline_tracker: BaselineTracker | None = None
    schema_change_detector: SchemaChangeDetector | None = None
    quarantine_sink: QuarantineSink | None = None


async def _validate_ingest_integrity(
    rows: list[dict[str, Any]],
    cfg: IngestIntegrityConfig,
    source_id: str,
    validators: IngestValidators,
    audit: AuditLogger | None,
    *,
    current_schema_hash: str | None = None,
) -> list[dict[str, Any]]:
    """Run the four-step ingest-integrity pipeline over ``rows``.

    Args:
        rows: Coerced rows from :func:`nautilus.adapters.rest._coerce_rows`.
        cfg: Per-source :class:`IngestIntegrityConfig`.
        source_id: Stable source identifier (``SourceConfig.id``).
        validators: Precompiled bundle from ``adapter.connect()``.
        audit: Optional audit sink for anomaly / pass-through sub-events.
        current_schema_hash: Optional publisher schema hash for step (1).
            ``None`` skips the schema-change check (sources with no
            upstream schema signal still get row-level validation).

    Returns:
        The rows surviving validation (``ok_rows`` under ``quarantine`` /
        ``reject`` modes; the original ``rows`` under ``pass-through``),
        optionally post-processed by ``cfg.corroboration_callback``.

    Raises:
        IngestPausedError: From the schema-change detector under
            ``on_publisher_schema_change="pause"``.
        SchemaViolationError: Under ``on_schema_violation="reject"`` when
            any row fails JSON-schema validation.
    """
    # ------------------------------------------------------------------
    # Step 1 — publisher schema-change gate (design §749-750).
    # ------------------------------------------------------------------
    if current_schema_hash is not None and validators.schema_change_detector is not None:
        await validators.schema_change_detector.check(
            source_id,
            current_schema_hash=current_schema_hash,
            mode=cfg.on_publisher_schema_change,
        )

    # ------------------------------------------------------------------
    # Step 2 — per-row schema validation + violation routing.
    # ------------------------------------------------------------------
    ok_rows, violations = validators.schema_validator.validate(rows)

    if violations:
        if cfg.on_schema_violation == "quarantine":
            # Route each violation to the quarantine sink + audit trail.
            # Falls through on missing sink (fire-and-forget contract —
            # misconfiguration surfaces via the log warning rather than
            # by halting the batch mid-flight).
            if validators.quarantine_sink is not None:
                for row, reason in violations:
                    await validators.quarantine_sink.record(
                        source_id,
                        row,
                        reason,
                        schema_hash=current_schema_hash,
                    )
                    _emit_ingest_subevent(
                        audit,
                        source_id=source_id,
                        subevent="ingest_quarantine",
                        reason=reason,
                        schema_hash=current_schema_hash,
                    )
            else:  # pragma: no cover — exercised via adapter integration tests
                _LOG.warning(
                    "ingest quarantine mode configured but no QuarantineSink "
                    "wired for source=%s; %d violation(s) dropped",
                    source_id,
                    len(violations),
                )
            rows_out = ok_rows
        elif cfg.on_schema_violation == "reject":
            # Hard-fail the batch on the first violation; caller receives
            # ``SchemaViolationError`` and the broker maps it to
            # ``sources_errored`` (design §1024).
            _first_row, first_reason = violations[0]
            raise SchemaViolationError(
                f"schema violation in source '{source_id}': {first_reason} "
                f"(total={len(violations)})"
            )
        else:  # pass-through
            for _row, reason in violations:
                _emit_ingest_subevent(
                    audit,
                    source_id=source_id,
                    subevent="ingest_violation_passthrough",
                    reason=reason,
                    schema_hash=current_schema_hash,
                )
            rows_out = rows
    else:
        rows_out = ok_rows

    # ------------------------------------------------------------------
    # Step 3 — baseline update + anomaly check (non-blocking audit).
    # ------------------------------------------------------------------
    if validators.baseline_tracker is not None:
        anomalies = await validators.baseline_tracker.update_and_check(source_id, rows_out)
        for anomaly in anomalies:
            _LOG.warning(
                "ingest anomaly source=%s type=%s z=%.2f observed=%s mean=%s stddev=%s",
                source_id,
                anomaly.get("baseline_type"),
                anomaly.get("z_score", 0.0),
                anomaly.get("observed"),
                anomaly.get("mean"),
                anomaly.get("stddev"),
            )
            _emit_ingest_subevent(
                audit,
                source_id=source_id,
                subevent="ingest_anomaly",
                reason=(
                    f"baseline_type={anomaly.get('baseline_type')} "
                    f"z={anomaly.get('z_score', 0.0):.2f} "
                    f"observed={anomaly.get('observed')} "
                    f"mean={anomaly.get('mean')} "
                    f"stddev={anomaly.get('stddev')}"
                ),
                schema_hash=current_schema_hash,
            )

    # ------------------------------------------------------------------
    # Step 4 — optional corroboration callback (design §755-757).
    # ------------------------------------------------------------------
    if cfg.corroboration_callback is not None:
        try:
            callback_result = cfg.corroboration_callback(rows_out)
            # The user hook may return a coroutine (if they defined it async);
            # await transparently so callers can choose either shape.
            if inspect.isawaitable(callback_result):
                rows_out = await callback_result
            else:
                rows_out = callback_result
        except Exception as exc:  # pragma: no cover — user hook path
            _LOG.warning("corroboration callback failed for source=%s: %s", source_id, exc)
            _emit_ingest_subevent(
                audit,
                source_id=source_id,
                subevent="corroboration_failed",
                reason=str(exc),
                schema_hash=current_schema_hash,
            )

    return rows_out


def _emit_ingest_subevent(
    audit: AuditLogger | None,
    *,
    source_id: str,
    subevent: str,
    reason: str,
    schema_hash: str | None,
) -> None:
    """Emit an ``event_type="request"`` audit entry carrying an ingest sub-event.

    Design lines 1023-1024 document the ``extra={ingest_quarantine: ...}``
    pattern; the current ``AuditEntry`` shape has no ``extra`` column so we
    stash the sub-event kind + reason + schema-hash in ``rule_trace``
    (identical convention used by :func:`SchemaChangeDetector._emit_schema_change_audit`
    at ``nautilus/ingest/schema_change.py``). Operators recover the details
    with a simple grep on the JSONL audit stream.
    """
    if audit is None:
        return
    entry = AuditEntry(
        event_type="request",
        timestamp=datetime.now(UTC),
        request_id=f"{subevent}-{uuid.uuid4()}",
        agent_id="system",
        raw_intent="",
        facts_asserted_summary={},
        routing_decisions=[],
        scope_constraints=[],
        denial_records=[],
        error_records=[],
        rule_trace=[
            f"{subevent} source={source_id} reason={reason} schema_hash={schema_hash or 'none'}"
        ],
        sources_queried=[source_id],
        sources_denied=[],
        sources_skipped=[],
        sources_errored=[],
        attestation_token=None,
        duration_ms=0,
    )
    audit.emit(entry)
