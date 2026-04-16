"""Manual pipeline span context managers for broker request tracing."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

try:
    from opentelemetry import trace

    _tracer = trace.get_tracer("nautilus")
    _has_otel = True
except ImportError:
    _has_otel = False

from nautilus.observability._noop import NoOpSpan

# Span name constants
SPAN_BROKER_REQUEST = "broker.request"
SPAN_INTENT_ANALYSIS = "intent_analysis"
SPAN_FATHOM_ROUTING = "fathom_routing"
SPAN_ADAPTER_FAN_OUT = "adapter_fan_out"
SPAN_SYNTHESIS = "synthesis"
SPAN_AUDIT_EMIT = "audit_emit"
SPAN_ATTESTATION_SIGN = "attestation_sign"


def adapter_span_name(source_id: str) -> str:
    """Return the span name for a specific adapter, e.g. ``adapter.influxdb``."""
    return f"adapter.{source_id}"


def build_request_attributes(
    agent_id: str,
    **extra: Any,
) -> dict[str, Any]:
    """Build a span-attribute dict for a top-level broker request.

    Centralises the attribute schema so callers never construct raw dicts.
    """
    attrs: dict[str, Any] = {"agent_id": agent_id}
    attrs.update(extra)
    return attrs


@contextmanager
def broker_span(name: str, attributes: dict[str, Any] | None = None):
    """Yield an OTel span if available, otherwise a no-op span."""
    if not _has_otel:
        with NoOpSpan(name) as span:
            yield span
        return
    with _tracer.start_as_current_span(name, attributes=attributes or {}) as span:
        yield span
