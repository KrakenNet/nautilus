"""Unit coverage for :mod:`nautilus.core.circuit_breaker` (Task 3, TD-5).

Pins the 3-state FSM invariants via five async tests:

(a) ``closed -> open`` after ``failure_threshold=3`` consecutive exceptions
    inside ``async with``.
(b) ``open -> half_open`` once ``reset_timeout`` seconds have elapsed (time
    mocked via ``monkeypatch`` on ``time.monotonic``).
(c) ``half_open`` success -> ``closed`` with failure counter reset.
(d) ``half_open`` failure -> ``open`` with timer reset.
(e) :class:`CircuitOpenError` raised immediately while ``open`` (body does
    NOT execute).
"""

from __future__ import annotations

import pytest

from nautilus.core.circuit_breaker import CircuitBreaker, CircuitOpenError


class _BoomError(RuntimeError):
    """Sentinel exception raised inside the breaker context."""


@pytest.mark.unit
async def test_closed_to_open_after_threshold_failures() -> None:
    breaker = CircuitBreaker(failure_threshold=3, reset_timeout=60.0, name="t1")
    assert breaker.state == "closed"

    for _ in range(3):
        with pytest.raises(_BoomError):
            async with breaker:
                raise _BoomError("fail")

    assert breaker.state == "open"


@pytest.mark.unit
async def test_open_to_half_open_after_reset_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"t": 1000.0}

    def fake_monotonic() -> float:
        return clock["t"]

    monkeypatch.setattr(
        "nautilus.core.circuit_breaker.time.monotonic",
        fake_monotonic,
    )

    breaker = CircuitBreaker(failure_threshold=2, reset_timeout=30.0, name="t2")

    # Trip to open.
    for _ in range(2):
        with pytest.raises(_BoomError):
            async with breaker:
                raise _BoomError("fail")
    assert breaker.state == "open"

    # Advance past the reset window; next entry should be half_open.
    clock["t"] += 31.0

    async with breaker:
        assert breaker.state == "half_open"


@pytest.mark.unit
async def test_half_open_success_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"t": 0.0}
    monkeypatch.setattr(
        "nautilus.core.circuit_breaker.time.monotonic",
        lambda: clock["t"],
    )

    breaker = CircuitBreaker(failure_threshold=2, reset_timeout=10.0, name="t3")
    for _ in range(2):
        with pytest.raises(_BoomError):
            async with breaker:
                raise _BoomError("fail")
    assert breaker.state == "open"

    clock["t"] += 11.0

    # Successful half-open probe.
    async with breaker:
        assert breaker.state == "half_open"

    assert breaker.state == "closed"
    # Counter reset: need full threshold again before re-opening.
    with pytest.raises(_BoomError):
        async with breaker:
            raise _BoomError("fail")
    assert breaker.state == "closed"


@pytest.mark.unit
async def test_half_open_failure_reopens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"t": 0.0}
    monkeypatch.setattr(
        "nautilus.core.circuit_breaker.time.monotonic",
        lambda: clock["t"],
    )

    breaker = CircuitBreaker(failure_threshold=2, reset_timeout=10.0, name="t4")
    for _ in range(2):
        with pytest.raises(_BoomError):
            async with breaker:
                raise _BoomError("fail")
    assert breaker.state == "open"
    opened_at_first = clock["t"]

    clock["t"] += 11.0  # elapsed past reset_timeout
    with pytest.raises(_BoomError):
        async with breaker:
            assert breaker.state == "half_open"
            raise _BoomError("fail")

    assert breaker.state == "open"
    # Timer reset: next entry BEFORE the new window should still be open.
    clock["t"] += 1.0
    assert clock["t"] - opened_at_first > 10.0  # old timer would have expired
    with pytest.raises(CircuitOpenError):
        async with breaker:
            pytest.fail("body must not execute while open")


@pytest.mark.unit
async def test_circuit_open_error_raised_while_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"t": 0.0}
    monkeypatch.setattr(
        "nautilus.core.circuit_breaker.time.monotonic",
        lambda: clock["t"],
    )

    breaker = CircuitBreaker(failure_threshold=2, reset_timeout=60.0, name="t5")
    for _ in range(2):
        with pytest.raises(_BoomError):
            async with breaker:
                raise _BoomError("fail")
    assert breaker.state == "open"

    body_ran = False

    with pytest.raises(CircuitOpenError):
        async with breaker:
            body_ran = True

    assert body_ran is False
