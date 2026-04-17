"""Unit tests for OTel span and metrics no-op/fallback behaviour.

Tests exercise the public API surface of ``nautilus.observability.spans``,
``nautilus.observability.metrics``, and ``nautilus.observability._noop``
without requiring OpenTelemetry packages to be installed.
"""

from __future__ import annotations

from nautilus.observability._noop import NoOpMetrics, NoOpSpan, NoOpSpanObj
from nautilus.observability.metrics import (  # pyright: ignore[reportPrivateUsage]
    NautilusMetrics,
    _NoOpInstrument,
)
from nautilus.observability.spans import (
    SPAN_ADAPTER_FAN_OUT,
    SPAN_ATTESTATION_SIGN,
    SPAN_AUDIT_EMIT,
    SPAN_BROKER_REQUEST,
    SPAN_FATHOM_ROUTING,
    SPAN_INTENT_ANALYSIS,
    SPAN_SYNTHESIS,
    adapter_span_name,
    broker_span,
    build_request_attributes,
)

# ------------------------------------------------------------------
# Span constants
# ------------------------------------------------------------------


class TestSpanConstants:
    """Span name constants are defined and non-empty."""

    def test_broker_request(self) -> None:
        assert SPAN_BROKER_REQUEST == "broker.request"

    def test_intent_analysis(self) -> None:
        assert SPAN_INTENT_ANALYSIS == "intent_analysis"

    def test_fathom_routing(self) -> None:
        assert SPAN_FATHOM_ROUTING == "fathom_routing"

    def test_adapter_fan_out(self) -> None:
        assert SPAN_ADAPTER_FAN_OUT == "adapter_fan_out"

    def test_synthesis(self) -> None:
        assert SPAN_SYNTHESIS == "synthesis"

    def test_audit_emit(self) -> None:
        assert SPAN_AUDIT_EMIT == "audit_emit"

    def test_attestation_sign(self) -> None:
        assert SPAN_ATTESTATION_SIGN == "attestation_sign"


class TestAdapterSpanName:
    """``adapter_span_name`` helper produces correct names."""

    def test_basic(self) -> None:
        assert adapter_span_name("influxdb") == "adapter.influxdb"

    def test_with_dots(self) -> None:
        assert adapter_span_name("pg.vector") == "adapter.pg.vector"


class TestBuildRequestAttributes:
    """``build_request_attributes`` builds attribute dicts."""

    def test_minimal(self) -> None:
        attrs = build_request_attributes(agent_id="a1")
        assert attrs == {"agent_id": "a1"}

    def test_with_extras(self) -> None:
        attrs = build_request_attributes(agent_id="a1", model="gpt-4")
        assert attrs == {"agent_id": "a1", "model": "gpt-4"}


# ------------------------------------------------------------------
# NoOpSpan context manager (_noop module)
# ------------------------------------------------------------------


class TestNoOpSpan:
    """``NoOpSpan`` context manager works without errors."""

    def test_enter_exit(self) -> None:
        with NoOpSpan("test") as span:
            assert span is not None

    def test_yields_noop_span_obj(self) -> None:
        with NoOpSpan("test") as span:
            assert isinstance(span, NoOpSpanObj)

    def test_set_attribute(self) -> None:
        with NoOpSpan("test") as span:
            span.set_attribute("key", "value")  # should not raise

    def test_set_status(self) -> None:
        with NoOpSpan("test") as span:
            span.set_status("OK")  # should not raise

    def test_record_exception(self) -> None:
        with NoOpSpan("test") as span:
            span.record_exception(RuntimeError("boom"))  # should not raise


# ------------------------------------------------------------------
# NoOpMetrics (_noop module)
# ------------------------------------------------------------------


class TestNoOpMetrics:
    """``NoOpMetrics`` counter/histogram operations are silent no-ops."""

    def test_counter(self) -> None:
        m = NoOpMetrics()
        m.counter("test.count", 1)  # should not raise

    def test_counter_with_attrs(self) -> None:
        m = NoOpMetrics()
        m.counter("test.count", 5, source="db")

    def test_histogram(self) -> None:
        m = NoOpMetrics()
        m.histogram("test.duration", 0.42)  # should not raise

    def test_histogram_with_attrs(self) -> None:
        m = NoOpMetrics()
        m.histogram("test.duration", 1.5, unit="s")


# ------------------------------------------------------------------
# _NoOpInstrument (metrics module)
# ------------------------------------------------------------------


class TestNoOpInstrument:
    """``_NoOpInstrument`` .add() and .record() are silent no-ops."""

    def test_add(self) -> None:
        inst = _NoOpInstrument()
        inst.add(1)  # should not raise

    def test_add_with_attrs(self) -> None:
        inst = _NoOpInstrument()
        inst.add(5, attributes={"source": "db"})

    def test_record(self) -> None:
        inst = _NoOpInstrument()
        inst.record(0.42)  # should not raise

    def test_record_with_attrs(self) -> None:
        inst = _NoOpInstrument()
        inst.record(1.5, attributes={"unit": "s"})


# ------------------------------------------------------------------
# broker_span context manager (spans module)
# ------------------------------------------------------------------


class TestBrokerSpan:
    """``broker_span`` works as a no-op when OTel is not installed."""

    def test_no_error(self) -> None:
        with broker_span("test"):
            pass

    def test_yields_span_like_object(self) -> None:
        with broker_span("test") as span:
            assert span is not None

    def test_with_attributes(self) -> None:
        with broker_span("test", attributes={"key": "val"}) as span:
            assert span is not None

    def test_nested_spans(self) -> None:
        with broker_span("outer") as outer, broker_span("inner") as inner:
            assert outer is not None
            assert inner is not None


# ------------------------------------------------------------------
# NautilusMetrics (metrics module)
# ------------------------------------------------------------------


class TestNautilusMetrics:
    """``NautilusMetrics`` initializes and operates without error."""

    def test_init(self) -> None:
        m = NautilusMetrics()
        assert m is not None

    def test_counters_exist(self) -> None:
        m = NautilusMetrics()
        assert hasattr(m, "requests_total")
        assert hasattr(m, "routing_decisions_total")
        assert hasattr(m, "scope_denials_total")
        assert hasattr(m, "attestation_total")
        assert hasattr(m, "adapter_errors_total")
        assert hasattr(m, "session_exposure_flags_total")

    def test_histograms_exist(self) -> None:
        m = NautilusMetrics()
        assert hasattr(m, "request_duration")
        assert hasattr(m, "adapter_latency")
        assert hasattr(m, "fathom_evaluation_duration")

    def test_counter_add_noop(self) -> None:
        m = NautilusMetrics()
        m.requests_total.add(1)  # should not raise

    def test_histogram_record_noop(self) -> None:
        m = NautilusMetrics()
        m.request_duration.record(0.5)  # should not raise

    def test_counter_add_with_attributes(self) -> None:
        m = NautilusMetrics()
        m.adapter_errors_total.add(1, attributes={"adapter": "pg"})

    def test_histogram_record_with_attributes(self) -> None:
        m = NautilusMetrics()
        m.adapter_latency.record(0.1, attributes={"adapter": "influx"})
