"""``BasicSynthesizer`` — trivial per-source passthrough merge (design §3.6)."""

from __future__ import annotations

from typing import Any, ClassVar

from nautilus.core.models import AdapterResult


class BasicSynthesizer:
    """Pass-through synthesizer: returns ``{source_id: rows}`` unchanged.

    Per design §3.6, per-adapter runtime failures are pre-filtered into
    ``sources_errored`` by the broker before reaching this layer; therefore
    :meth:`merge` never raises.
    """

    # Declaring this ClassVar lets downstream code discriminate synthesizer
    # impls without isinstance() checks.
    kind: ClassVar[str] = "basic"

    def merge(self, results: list[AdapterResult]) -> dict[str, list[dict[str, Any]]]:
        """Return a ``{source_id: rows}`` mapping keyed by ``result.source_id``.

        Args:
            results: Per-source :class:`AdapterResult` values. Any carrying
                an ``error`` are skipped defensively.

        Returns:
            Mapping from ``source_id`` to a fresh copy of the adapter's rows.
        """
        merged: dict[str, list[dict[str, Any]]] = {}
        for result in results:
            # Any result reaching this point has no error (broker guarantee).
            # Defensive: still skip error-carrying results so a misuse cannot
            # smuggle stale rows into the response.
            if result.error is not None:
                continue
            merged[result.source_id] = list(result.rows)
        return merged


__all__ = ["BasicSynthesizer"]
