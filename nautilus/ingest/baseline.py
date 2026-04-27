"""``IngestBaselineStore`` + ``BaselineTracker`` — rolling-window anomaly gate (US-4).

Implements the ingest-integrity baseline layer (design §"Component
Responsibilities → BaselineTracker"; AC-4.9, AC-4.12; FR-20, FR-21, FR-30,
FR-33, FR-34, FR-35).

The store is a thin :class:`~nautilus.core.postgres_store.BasePostgresStore`
subclass over the ``nautilus_ingest_baseline`` table (DDL block 2 —
design lines 348-358). The tracker sits on top and exposes a single async
hook the ingest orchestrator invokes per batch::

    anomalies = await baseline.update_and_check(source_id, rows)

``update_and_check`` records a fresh sample (row count today; extensible
to field-level stats), rolls the in-window history forward, computes
``(mean, stddev)`` over the kept samples, and flags the current observation
if ``|z| > anomaly_sigma``. Each flagged anomaly fires the
``nautilus.ingest.anomaly.total`` counter (design line 1046) with
``{source_id, baseline_type}`` attributes.

The tracker holds in-memory sample history so per-batch z-scores are cheap;
the store persists compact ``(mean, stddev, sample_size)`` snapshots for
survival across restarts + for OQ-3 retention (``DELETE FROM ... WHERE
created_at < NOW() - INTERVAL '90 days'`` run out-of-band by ops).

OQ-3 / Task notes:

- Auto-prune is explicitly out of scope. The baseline-retention window from
  :class:`~nautilus.ingest.config.IngestIntegrityConfig.baseline_retention`
  is documented for ops; no background sweeper is wired here.
- Memory fallback (:class:`FailureMode` ``"fallback_memory"``) degrades to
  a dict keyed by ``(source_id, baseline_type, window_start)``. The process
  loses baselines on restart but the pipeline keeps flowing — matches the
  source-state store's degradation contract.
"""

from __future__ import annotations

import json
import logging
import math
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from nautilus.core.postgres_store import BasePostgresStore
from nautilus.core.types import FailureMode


class _NoOpCounter:
    """Fallback counter used when OpenTelemetry isn't installed."""

    def add(
        self,
        amount: float = 1,  # noqa: ARG002 — keep the OTel signature
        attributes: dict[str, Any] | None = None,  # noqa: ARG002
    ) -> None:
        return None


def _build_anomaly_counter() -> Any:
    """Create the ``nautilus.ingest.anomaly.total`` counter (design line 1046).

    Separated into a helper so ``_ANOMALY_COUNTER`` is assigned exactly once
    at module scope (``reportConstantRedefinition``-clean) while still
    degrading to a no-op when OpenTelemetry isn't on the path.
    """
    try:
        from opentelemetry import metrics as _otel_metrics
    except ImportError:  # pragma: no cover — OTel is a soft dep
        return _NoOpCounter()
    return _otel_metrics.get_meter("nautilus").create_counter(
        "nautilus.ingest.anomaly.total",
        description="Ingest-integrity baseline anomalies flagged",
    )


_ANOMALY_COUNTER: Any = _build_anomaly_counter()

__all__ = [
    "BaselineSnapshot",
    "BaselineTracker",
    "IngestBaselineStore",
    "IngestBaselineStoreUnavailableError",
]


_LOG = logging.getLogger(__name__)


# DDL Block 2 — design.md lines 348-358, verbatim.
_DDL: str = (
    "CREATE TABLE IF NOT EXISTS nautilus_ingest_baseline ("
    "id UUID PRIMARY KEY, "
    "source_id TEXT NOT NULL, "
    "baseline_type TEXT NOT NULL, "
    "window_start TIMESTAMPTZ NOT NULL, "
    "window_end TIMESTAMPTZ NOT NULL, "
    "baseline_data JSONB NOT NULL, "
    "created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
    "); "
    "CREATE INDEX IF NOT EXISTS ix_nautilus_ingest_baseline_source_window "
    "ON nautilus_ingest_baseline (source_id, window_end DESC)"
)


# Accept only whole-number durations with a single d/h/m suffix.
_WINDOW_RE = re.compile(r"^(\d+)([dhm])$")


def _parse_window(window: str) -> timedelta:
    """Parse a baseline-window string like ``"7d"`` / ``"24h"`` / ``"30m"``.

    Raises:
        ValueError: on empty / missing-suffix / non-integer / non-positive
        input. The orchestrator surfaces the raise as a config-level error
        so operators see the bad duration near the ``IngestIntegrityConfig``
        load site rather than mid-request.
    """
    m = _WINDOW_RE.match(window)
    if m is None:
        raise ValueError(
            f"invalid baseline window {window!r}: expected '<N><unit>' "
            "with unit in {d,h,m} (e.g. '7d', '24h', '30m')"
        )
    amount = int(m.group(1))
    if amount <= 0:
        raise ValueError(f"baseline window must be positive, got {window!r}")
    unit = m.group(2)
    if unit == "d":
        return timedelta(days=amount)
    if unit == "h":
        return timedelta(hours=amount)
    return timedelta(minutes=amount)


def _z_score(observed: float, mean: float, stddev: float) -> float:
    """``(observed - mean) / stddev`` with ``stddev == 0`` fail-safe.

    Returns ``0.0`` when ``stddev`` is zero so a flat baseline cannot drive
    a spurious infinite-z-score anomaly. Callers rely on this to keep the
    gate quiet during the first few batches (before enough variance has
    accumulated to produce a meaningful stddev).
    """
    if stddev == 0.0 or not math.isfinite(stddev):
        return 0.0
    return (observed - mean) / stddev


@dataclass(frozen=True, slots=True)
class BaselineSnapshot:
    """Immutable projection of one ``nautilus_ingest_baseline`` row.

    Stored as JSONB under ``baseline_data`` so future baseline types
    (quantile bands, cardinality sketches) can extend the column without
    another migration. The snapshot's numeric triple is the shape we care
    about today.
    """

    source_id: str
    baseline_type: str
    window_start: datetime
    window_end: datetime
    mean: float
    stddev: float
    sample_size: int
    computed_at: datetime


class IngestBaselineStoreUnavailableError(Exception):
    """Raised when a ``fail_closed`` :class:`IngestBaselineStore` cannot reach PG."""


class IngestBaselineStore(BasePostgresStore):
    """asyncpg-backed persistence for baseline snapshots.

    One row per ``(source_id, baseline_type, window_start)`` — upserts on
    the ``PRIMARY KEY (id)`` with a logical-key lookup via the
    source+window index (``ix_nautilus_ingest_baseline_source_window``).

    This class deliberately does not maintain an in-process sample buffer;
    the :class:`BaselineTracker` owns that concern. The store is a pure
    read/write facade over the persisted numeric triple.
    """

    _DDL: str = _DDL
    _TABLE: str = "nautilus_ingest_baseline"

    def __init__(
        self,
        dsn: str,
        *,
        on_failure: FailureMode = "fail_closed",
    ) -> None:
        super().__init__(dsn, on_failure=on_failure)

    # ------------------------------------------------------------------
    # Abstract hooks
    # ------------------------------------------------------------------

    def _init_memory_backend(self) -> dict[tuple[str, str, datetime], BaselineSnapshot]:
        """Return a fresh empty dict keyed by ``(source_id, type, window_start)``."""
        _LOG.warning(
            "ingest_baseline backend degraded to memory: baselines will not "
            "survive restart (table=%s)",
            self._TABLE,
        )
        return {}

    def _unavailable_error(self) -> type[Exception]:
        return IngestBaselineStoreUnavailableError

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def upsert(self, snapshot: BaselineSnapshot) -> None:
        """Persist ``snapshot`` — memory or Postgres, matching the store mode."""
        if self._mode == "degraded_memory":
            backend: dict[tuple[str, str, datetime], BaselineSnapshot] = self._memory_backend
            key = (snapshot.source_id, snapshot.baseline_type, snapshot.window_start)
            backend[key] = snapshot
            return
        if self._pool is None:
            raise IngestBaselineStoreUnavailableError(
                "IngestBaselineStore.upsert() called before setup() succeeded"
            )
        payload = json.dumps(
            {
                "mean": snapshot.mean,
                "stddev": snapshot.stddev,
                "sample_size": snapshot.sample_size,
            }
        )
        await self._pool.execute(
            "INSERT INTO nautilus_ingest_baseline "
            "(id, source_id, baseline_type, window_start, window_end, "
            "baseline_data, created_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7)",
            uuid.uuid4(),
            snapshot.source_id,
            snapshot.baseline_type,
            snapshot.window_start,
            snapshot.window_end,
            payload,
            snapshot.computed_at,
        )

    async def get(self, source_id: str, baseline_type: str) -> BaselineSnapshot | None:
        """Return the most recent baseline for ``(source_id, baseline_type)`` or ``None``."""
        if self._mode == "degraded_memory":
            backend: dict[tuple[str, str, datetime], BaselineSnapshot] = self._memory_backend
            candidates = [
                snap
                for (sid, btype, _ws), snap in backend.items()
                if sid == source_id and btype == baseline_type
            ]
            if not candidates:
                return None
            return max(candidates, key=lambda s: s.window_end)
        if self._pool is None:
            raise IngestBaselineStoreUnavailableError(
                "IngestBaselineStore.get() called before setup() succeeded"
            )
        row: Any = await self._pool.fetchrow(
            "SELECT source_id, baseline_type, window_start, window_end, "
            "baseline_data, created_at "
            "FROM nautilus_ingest_baseline "
            "WHERE source_id = $1 AND baseline_type = $2 "
            "ORDER BY window_end DESC LIMIT 1",
            source_id,
            baseline_type,
        )
        if row is None:
            return None
        data = row["baseline_data"]
        if isinstance(data, str):
            data = json.loads(data)
        return BaselineSnapshot(
            source_id=row["source_id"],
            baseline_type=row["baseline_type"],
            window_start=row["window_start"],
            window_end=row["window_end"],
            mean=float(data["mean"]),
            stddev=float(data["stddev"]),
            sample_size=int(data["sample_size"]),
            computed_at=row["created_at"],
        )


# ---------------------------------------------------------------------------
# BaselineTracker
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Sample:
    """One numeric observation timestamped so the window trim stays O(n)."""

    value: float
    at: datetime


class BaselineTracker:
    """Rolling-window statistical baseline gate over ingest batches (AC-4.9).

    Attributes:
        store: Persistence facade; survives across broker restarts.
        baseline_window: Duration string like ``"7d"`` / ``"24h"`` / ``"30m"``.
        anomaly_sigma: ``|z|`` threshold above which a sample is flagged.

    The tracker owns two concerns:

    1. **Sample history** — an in-memory ``deque``-like list per
       ``(source_id, baseline_type)`` trimmed to ``baseline_window`` before
       every stats computation.
    2. **Anomaly detection** — compute mean/stddev from the kept samples,
       score the observation, emit a counter + record per ``|z|`` breach.

    The store's persisted snapshot is consulted when the in-memory history
    is empty (cold start), so restarts don't lose the gate immediately.
    """

    def __init__(
        self,
        store: IngestBaselineStore,
        *,
        baseline_window: str = "7d",
        anomaly_sigma: float = 3.0,
    ) -> None:
        self._store: IngestBaselineStore = store
        self._window: timedelta = _parse_window(baseline_window)
        self._sigma: float = anomaly_sigma
        # Keyed by (source_id, baseline_type) → list[_Sample].
        self._samples: dict[tuple[str, str], list[_Sample]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def update_and_check(
        self, source_id: str, rows: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Record a sample for ``rows``; return a list of anomaly records.

        Today's baselines:

        * ``row_count`` — number of rows in the batch.

        Extension point: add more baseline types by appending to the
        ``observations`` list below. Each entry is a pair
        ``(baseline_type, observed_value)``; the rest of the method treats
        them uniformly.
        """
        now = datetime.now(UTC)

        # Enumerate observed scalars per baseline_type. Ordered so tests can
        # rely on determinism when multiple anomalies fire on the same call.
        observations: list[tuple[str, float]] = [("row_count", float(len(rows)))]

        anomalies: list[dict[str, Any]] = []

        for baseline_type, observed in observations:
            # Hydrate the in-memory history from persisted snapshot on cold start.
            await self._hydrate_if_cold(source_id, baseline_type)

            # Score *before* recording so the new sample doesn't move the
            # mean it's being compared against (standard z-score hygiene).
            mean, stddev, sample_size = self._aggregate(source_id, baseline_type, now)
            z = _z_score(observed, mean, stddev)

            if sample_size > 0 and abs(z) > self._sigma:
                anomaly = {
                    "baseline_type": baseline_type,
                    "observed": observed,
                    "mean": mean,
                    "stddev": stddev,
                    "z_score": z,
                    "window_start": now - self._window,
                    "window_end": now,
                    "sample_size": sample_size,
                }
                anomalies.append(anomaly)
                _ANOMALY_COUNTER.add(
                    1,
                    attributes={
                        "source_id": source_id,
                        "baseline_type": baseline_type,
                    },
                )

            # Record the fresh sample *after* scoring.
            self._record_sample(source_id, baseline_type, observed, now)

            # Persist the updated stats so restarts don't lose the gate.
            new_mean, new_stddev, new_n = self._aggregate(source_id, baseline_type, now)
            await self._store.upsert(
                BaselineSnapshot(
                    source_id=source_id,
                    baseline_type=baseline_type,
                    window_start=now - self._window,
                    window_end=now,
                    mean=new_mean,
                    stddev=new_stddev,
                    sample_size=new_n,
                    computed_at=now,
                )
            )

        return anomalies

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_sample(
        self,
        source_id: str,
        baseline_type: str,
        value: float,
        at: datetime,
    ) -> None:
        """Append a new sample to the in-memory history."""
        self._samples[(source_id, baseline_type)].append(_Sample(value=value, at=at))

    def _aggregate(
        self, source_id: str, baseline_type: str, now: datetime
    ) -> tuple[float, float, int]:
        """Trim out-of-window samples and return ``(mean, stddev, n)``.

        Uses a population stddev (divide by n, not n-1) — with small
        sample sizes this keeps the gate more sensitive, and with the
        default 7d window the difference is dwarfed by sample noise.
        """
        cutoff = now - self._window
        samples = self._samples[(source_id, baseline_type)]
        # In-place trim: keep only samples inside the rolling window.
        kept = [s for s in samples if s.at >= cutoff]
        self._samples[(source_id, baseline_type)] = kept

        n = len(kept)
        if n == 0:
            return 0.0, 0.0, 0
        mean = sum(s.value for s in kept) / n
        var = sum((s.value - mean) ** 2 for s in kept) / n
        stddev = math.sqrt(var)
        return mean, stddev, n

    async def _hydrate_if_cold(self, source_id: str, baseline_type: str) -> None:
        """Seed the in-memory history from the persisted snapshot on cold start.

        Called before every scoring pass so a freshly-created tracker with
        an empty buffer still honours the last-known baseline. We only
        synthesize samples when the in-memory history is empty AND the
        store has a row; otherwise we'd double-count the persisted stats.
        """
        key = (source_id, baseline_type)
        if self._samples[key]:
            return
        snap = await self._store.get(source_id, baseline_type)
        if snap is None or snap.sample_size <= 0:
            return
        # Synthesize two samples that reproduce the persisted (mean, stddev)
        # exactly: ``mean ± stddev``. With sample_size>=2 this is a
        # mathematically faithful recreation (var = stddev**2 for n=2 when
        # placed at mean±stddev).
        anchor = snap.computed_at
        self._samples[key].append(_Sample(value=snap.mean - snap.stddev, at=anchor))
        self._samples[key].append(_Sample(value=snap.mean + snap.stddev, at=anchor))
