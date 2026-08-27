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

    1. Create TracerProvider with OTLP HTTP exporter (traces -> Tempo)
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
    tracer_provider = TracerProvider(resource=resource)
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

    # --- FastAPI auto-instrumentation ---
    FastAPIInstrumentor.instrument_app(app)
