"""Observability package — optional OTel integration with graceful no-op."""

from __future__ import annotations

import os
from typing import Any


def setup_otel(app: Any, service_name: str = "nautilus") -> None:
    """Instrument *app* with OpenTelemetry if available.

    No-op when:
    - ``OTEL_SDK_DISABLED=true`` environment variable is set
    - OTel packages are not installed (``ImportError`` caught)
    """
    if os.environ.get("OTEL_SDK_DISABLED", "").lower() == "true":
        return

    try:
        from nautilus.observability.instrumentation import setup  # type: ignore[import-not-found]

        setup(app, service_name)
    except ImportError:
        pass
