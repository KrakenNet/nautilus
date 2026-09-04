"""Prometheus metrics for the RKM proposal queue (AC-35.9.f).

Gauges scraped lazily at collection time:
- ``nautilus_rkm_queue_depth``        — pending proposal count
- ``nautilus_rkm_queue_oldest_age_seconds`` — wall-time age of oldest pending proposal
- ``nautilus_ruleset_info{ruleset_hash}`` — the policy this replica loaded

Usage::

    from nautilus.core.metrics import register_rkm_queue

    # Call once at app startup with a zero-argument callable that returns
    # the live ProposalQueue instance (or None when not yet initialised).
    register_rkm_queue(lambda: app.state.proposal_queue)
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import TYPE_CHECKING

# prometheus-client lives in the optional ``otel`` extra; importing this module
# without it must not crash. Type-checking always sees the real symbols (run
# pyright with the ``otel`` extra installed); at runtime we degrade to no-ops.
if TYPE_CHECKING:
    from prometheus_client import REGISTRY
    from prometheus_client.metrics_core import GaugeMetricFamily
    from prometheus_client.registry import Collector

    _has_prometheus = True
else:
    try:
        from prometheus_client import REGISTRY
        from prometheus_client.metrics_core import GaugeMetricFamily
        from prometheus_client.registry import Collector

        _has_prometheus = True
    except ImportError:
        _has_prometheus = False
        REGISTRY = None
        GaugeMetricFamily = object
        Collector = object


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


# Module-level singleton — registered once on import (only when prometheus is
# installed via the ``otel`` extra; otherwise metrics degrade to a no-op).
_collector = _RkmQueueCollector()
if _has_prometheus:
    with contextlib.suppress(Exception):
        REGISTRY.register(_collector)


class _RulesetCollector(Collector):
    """Names the ruleset this replica loaded, as a scrape-time label.

    Every rolling deploy passes through a state where two replicas hold
    different rulesets, and the identical request then alternates allowed /
    denied behind the load balancer. ``GET /v1/rules`` exposes the hash but is
    itself load-balanced, so polling the Service just makes it flap -- there
    was no way to tell "two replicas disagree" from "someone changed the
    rules". A per-replica scrape target is: alert on more than one distinct
    ``ruleset_hash`` across the fleet.
    """

    def __init__(self) -> None:
        self._getter: Callable[[], object] | None = None

    def set_getter(self, getter: Callable[[], object]) -> None:
        self._getter = getter

    def describe(self) -> list[GaugeMetricFamily]:  # type: ignore[override]
        return [self._family()]

    def _family(self) -> GaugeMetricFamily:  # type: ignore[override]
        return GaugeMetricFamily(
            "nautilus_ruleset_info",
            "Always 1; the ruleset_hash label names the policy this replica runs",
            labels=["ruleset_hash"],
        )

    def collect(self) -> list[GaugeMetricFamily]:  # type: ignore[override]
        family = self._family()
        if self._getter is not None:
            with contextlib.suppress(Exception):
                ruleset_hash = self._getter()
                if ruleset_hash:
                    family.add_metric([str(ruleset_hash)], 1.0)
        return [family]


_ruleset_collector = _RulesetCollector()
if _has_prometheus:
    with contextlib.suppress(Exception):
        REGISTRY.register(_ruleset_collector)


def register_ruleset(getter: Callable[[], object]) -> None:
    """Wire the ruleset gauge to a callable returning this replica's hash.

    Args:
        getter: Zero-argument callable returning the ``ruleset_hash`` string
                (or ``None`` before the broker is ready). Called on every
                scrape — keep it cheap.
    """
    _ruleset_collector.set_getter(getter)


def register_rkm_queue(getter: Callable[[], object]) -> None:
    """Wire the collector to a callable that returns the live ProposalQueue.

    Args:
        getter: Zero-argument callable returning the ``ProposalQueue`` (or
                ``None`` when the queue is not yet initialised).  Called on
                every Prometheus scrape — keep it cheap.
    """
    _collector.set_getter(getter)


__all__ = ["register_rkm_queue", "register_ruleset"]
