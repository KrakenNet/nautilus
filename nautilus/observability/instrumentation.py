"""FastAPI auto-instrumentation with OpenTelemetry."""

from __future__ import annotations

import os
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter,
)
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.instrumentation.fastapi import (  # pyright: ignore[reportMissingTypeStubs]
    FastAPIInstrumentor,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def setup(app: Any, service_name: str = "nautilus") -> None:
    """Instrument *app* with OpenTelemetry tracing and metrics.

    1. Create TracerProvider, exporting over OTLP HTTP only when an endpoint
       is configured (traces -> Tempo)
    2. Create MeterProvider with Prometheus exporter
    3. Set global providers
    4. Instrument FastAPI app, excluding health endpoints
    """
    # Exclude health probes from tracing
    os.environ.setdefault(
        "OTEL_PYTHON_FASTAPI_EXCLUDED_URLS",
        "/healthz,/readyz",
    )

    resource = Resource.create({"service.name": service_name})

    # --- Traces (OTLP HTTP -> Tempo) ---
    # Only when there is somewhere to export to. ``OTLPSpanExporter()`` with no
    # endpoint defaults to localhost:4318, nothing listens there in the shipped
    # manifest, and every span batch then costs three WARNING retries plus an
    # ERROR -- 39 log lines a minute per replica of pure noise, which trips any
    # "alert on ERROR logs" rule and buries the broker's own diagnostics. The
    # only documented off-switch was ``OTEL_SDK_DISABLED``, which also drops the
    # metric reader below and takes every ``nautilus_*`` series with it, so the
    # choice was noise or blind dashboards. The provider is still installed, so
    # spans are created and a collector can be pointed at later.
    tracer_provider = TracerProvider(resource=resource)
    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or os.environ.get(
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
    ):
        span_exporter = OTLPSpanExporter()  # reads OTEL_EXPORTER_OTLP_ENDPOINT
        tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
    trace.set_tracer_provider(tracer_provider)

    # --- Metrics (Prometheus) ---
    # The reader registers a collector on ``prometheus_client``'s default
    # REGISTRY, which is the same registry ``GET /metrics`` serves via
    # ``generate_latest()``. Without it the MeterProvider has no reader, every
    # ``NautilusMetrics`` recording is discarded and /metrics exports only the
    # process_* series — which is what every shipped dashboard was querying
    # against.
    meter_provider = MeterProvider(resource=resource, metric_readers=[PrometheusMetricReader()])
    metrics.set_meter_provider(meter_provider)
    # Publish every counter at zero now that there is a reader to export them.
    # See NautilusMetrics.prime.
    from nautilus.core.broker import prime_metrics

    prime_metrics()

    # --- FastAPI auto-instrumentation ---
    FastAPIInstrumentor.instrument_app(app)
