"""Prometheus metrics for the RKM proposal queue (AC-35.9.f).

Two gauges scraped lazily at collection time:
- ``nautilus_rkm_queue_depth``        — pending proposal count
- ``nautilus_rkm_queue_oldest_age_seconds`` — wall-time age of oldest pending proposal

Usage::

    from nautilus.core.metrics import register_rkm_queue

    # Call once at app startup with a zero-argument callable that returns
    # the live ProposalQueue instance (or None when not yet initialised).
    register_rkm_queue(lambda: app.state.proposal_queue)
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable

from prometheus_client import REGISTRY
from prometheus_client.metrics_core import GaugeMetricFamily
from prometheus_client.registry import Collector


class _RkmQueueCollector(Collector):
    """Custom collector that reads queue metrics at scrape time."""

    def __init__(self) -> None:
        self._getter: Callable[[], object] | None = None

    def set_getter(self, getter: Callable[[], object]) -> None:
        self._getter = getter

    def describe(self) -> list[GaugeMetricFamily]:  # type: ignore[override]
        return [
            GaugeMetricFamily(
                "nautilus_rkm_queue_depth",
                "Current pending proposal queue size",
            ),
            GaugeMetricFamily(
                "nautilus_rkm_queue_oldest_age_seconds",
                "Wall-time age of the oldest pending proposal in seconds",
            ),
        ]

    def collect(self) -> list[GaugeMetricFamily]:  # type: ignore[override]
        depth_g = GaugeMetricFamily(
            "nautilus_rkm_queue_depth",
            "Current pending proposal queue size",
        )
        age_g = GaugeMetricFamily(
            "nautilus_rkm_queue_oldest_age_seconds",
            "Wall-time age of the oldest pending proposal in seconds",
        )
        if self._getter is not None:
            queue = self._getter()
            if queue is not None:
                with contextlib.suppress(Exception):
                    depth_g.add_metric([], float(queue.depth()))  # type: ignore[union-attr]
                    age_g.add_metric([], float(queue.oldest_age_seconds()))  # type: ignore[union-attr]
        return [depth_g, age_g]


# Module-level singleton — registered once on import.
_collector = _RkmQueueCollector()
with contextlib.suppress(Exception):
    REGISTRY.register(_collector)


def register_rkm_queue(getter: Callable[[], object]) -> None:
    """Wire the collector to a callable that returns the live ProposalQueue.

    Args:
        getter: Zero-argument callable returning the ``ProposalQueue`` (or
                ``None`` when the queue is not yet initialised).  Called on
                every Prometheus scrape — keep it cheap.
    """
    _collector.set_getter(getter)


__all__ = ["register_rkm_queue"]
