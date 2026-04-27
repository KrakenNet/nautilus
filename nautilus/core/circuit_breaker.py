"""Minimal async-aware circuit breaker (TD-5).

Three-state FSM: ``closed -> open -> half_open -> {closed, open}``.

On every state transition a structured log line is emitted. This stands in
for a proper counter until the observability layer grows one — see the
follow-up comment below.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from types import TracebackType
from typing import Literal

logger = logging.getLogger(__name__)

State = Literal["closed", "open", "half_open"]


class CircuitOpenError(RuntimeError):
    """Raised when the breaker short-circuits a call because it is ``open``."""


# TODO: wire NAUTILUS_SIGNER_CIRCUIT_STATE metric via observability/ when available
@dataclass
class CircuitBreaker:
    """Async circuit breaker with a three-state FSM."""

    failure_threshold: int = 3
    reset_timeout: float = 60.0
    name: str = "default"
    _state: State = field(default="closed", init=False)
    _failures: int = field(default=0, init=False)
    _opened_at: float = field(default=0.0, init=False)

    @property
    def state(self) -> State:
        return self._state

    def _transition(self, new_state: State) -> None:
        if new_state == self._state:
            return
        self._state = new_state
        logger.info(
            "circuit_breaker transition name=%s state=%s metric=NAUTILUS_SIGNER_CIRCUIT_STATE",
            self.name,
            new_state,
        )

    async def __aenter__(self) -> CircuitBreaker:
        if self._state == "open":
            if time.monotonic() - self._opened_at < self.reset_timeout:
                raise CircuitOpenError(f"circuit '{self.name}' is open")
            self._transition("half_open")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc is None:
            if self._state == "half_open":
                self._transition("closed")
            self._failures = 0
            return
        if self._state == "half_open":
            self._opened_at = time.monotonic()
            self._transition("open")
            return
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_at = time.monotonic()
            self._transition("open")
