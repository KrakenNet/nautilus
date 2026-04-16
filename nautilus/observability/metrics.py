"""Application-level counters and histograms for Nautilus."""

from __future__ import annotations

from typing import Any

try:
    from opentelemetry import metrics

    _meter = metrics.get_meter("nautilus")
    _has_otel = True
except ImportError:
    _has_otel = False


class _NoOpInstrument:
    """Instrument stub that silently discards all recordings."""

    def add(self, amount: float = 1, attributes: dict[str, Any] | None = None) -> None:  # noqa: ARG002
        pass

    def record(self, amount: float = 0, attributes: dict[str, Any] | None = None) -> None:  # noqa: ARG002
        pass


_NOOP = _NoOpInstrument()


class NautilusMetrics:
    """Six counters and three histograms for core Nautilus operations.

    When OpenTelemetry is not installed every attribute resolves to a
    no-op object whose ``.add()`` / ``.record()`` calls are silently
    discarded.
    """

    def __init__(self) -> None:
        if _has_otel:
            # -- Counters --
            self.requests_total = _meter.create_counter(
                "nautilus.requests.total",
                description="Total inbound requests",
            )
            self.routing_decisions_total = _meter.create_counter(
                "nautilus.routing.decisions.total",
                description="Routing decisions made",
            )
            self.scope_denials_total = _meter.create_counter(
                "nautilus.scope.denials.total",
                description="Scope-check denials",
            )
            self.attestation_total = _meter.create_counter(
                "nautilus.attestation.total",
                description="Attestation events",
            )
            self.adapter_errors_total = _meter.create_counter(
                "nautilus.adapter.errors.total",
                description="Adapter-level errors",
            )
            self.session_exposure_flags_total = _meter.create_counter(
                "nautilus.session.exposure_flags.total",
                description="Session exposure flags emitted",
            )

            # -- Histograms --
            self.request_duration = _meter.create_histogram(
                "nautilus.request.duration",
                description="End-to-end request duration",
                unit="s",
            )
            self.adapter_latency = _meter.create_histogram(
                "nautilus.adapter.latency",
                description="Adapter call latency",
                unit="s",
            )
            self.fathom_evaluation_duration = _meter.create_histogram(
                "nautilus.fathom.evaluation.duration",
                description="Fathom evaluation duration",
                unit="s",
            )
        else:
            # No-op fallback — safe to call .add() / .record() on every attr
            self.requests_total = _NOOP
            self.routing_decisions_total = _NOOP
            self.scope_denials_total = _NOOP
            self.attestation_total = _NOOP
            self.adapter_errors_total = _NOOP
            self.session_exposure_flags_total = _NOOP
            self.request_duration = _NOOP
            self.adapter_latency = _NOOP
            self.fathom_evaluation_duration = _NOOP
