"""No-op stubs for when OpenTelemetry is not installed."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any


@contextmanager
def NoOpSpan(name: str = "", **kwargs: Any) -> Generator[NoOpSpanObj]:  # noqa: N802
    """Context manager that yields a no-op span object."""
    yield NoOpSpanObj()


class NoOpSpanObj:
    """Dummy span with no-op methods."""

    def set_attribute(self, key: str, value: Any) -> None:  # noqa: ARG002
        pass

    def set_status(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        pass

    def record_exception(self, exception: BaseException) -> None:  # noqa: ARG002
        pass


class NoOpMetrics:
    """No-op metrics that silently discard all recordings."""

    def counter(self, name: str, value: float = 1, **attrs: Any) -> None:  # noqa: ARG002
        pass

    def histogram(self, name: str, value: float = 0, **attrs: Any) -> None:  # noqa: ARG002
        pass
