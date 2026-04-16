"""Temporal scope filter (design §3.9, FR-17).

Broker-side pre-adapter filter that drops :class:`ScopeConstraint`\\ s whose
``expires_at`` / ``valid_from`` ISO-8601 window has elapsed relative to the
current request time. Each dropped constraint produces a matching
:class:`DenialRecord` so the audit trail explains *why* the constraint was
removed before adapter fan-out.

Fail-closed: any malformed ISO-8601 timestamp causes the constraint to be
dropped with ``rule_name="scope-expired"`` — if we cannot parse the window,
we assume the worst case (expired).
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from nautilus.core.models import DenialRecord

if TYPE_CHECKING:
    from nautilus.core.models import ScopeConstraint


def _parse_iso8601(value: str) -> datetime | None:
    """Parse an ISO-8601 string; return ``None`` on any failure.

    ``datetime.fromisoformat`` only tolerates the trailing ``Z`` suffix on
    Python 3.11+; we normalise it to ``+00:00`` for safety across minor
    versions. Any ``ValueError`` (including out-of-range / missing parts)
    returns ``None`` so the caller can treat it as malformed.
    """
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    except AttributeError:
        return None


def _now_aware(now: datetime) -> datetime:
    """Ensure ``now`` is timezone-aware so comparisons against parsed ISO
    timestamps (which carry tzinfo after the ``Z`` → ``+00:00`` rewrite)
    do not raise ``TypeError: can't compare offset-naive vs offset-aware``.
    """
    if now.tzinfo is None:
        from datetime import UTC

        return now.replace(tzinfo=UTC)
    return now


def _normalise(parsed: datetime, now: datetime) -> datetime:
    """Align ``parsed`` tzinfo to ``now``'s so both sides compare safely."""
    if parsed.tzinfo is None and now.tzinfo is not None:
        return parsed.replace(tzinfo=now.tzinfo)
    return parsed


class TemporalFilter:
    """Apply ``expires_at`` / ``valid_from`` windows (design §3.9)."""

    @staticmethod
    def apply(
        constraints: dict[str, list[ScopeConstraint]],
        now: datetime,
    ) -> tuple[dict[str, list[ScopeConstraint]], list[DenialRecord]]:
        """Drop expired / not-yet-valid / malformed-window constraints.

        Returns ``(kept, denials)`` where ``kept`` preserves the original
        ``dict[source_id -> list[ScopeConstraint]]`` shape minus any dropped
        members, and ``denials`` lists one :class:`DenialRecord` per drop
        with ``rule_name="scope-expired"``.

        Empty lists are preserved in ``kept`` so downstream code can still
        key off ``source_id`` presence (the adapter fan-out treats an empty
        scope list as "no restrictions" — matching Phase 1 semantics).
        """
        now_tz = _now_aware(now)
        kept: dict[str, list[ScopeConstraint]] = {}
        denials: list[DenialRecord] = []
        for source_id, scope in constraints.items():
            surviving: list[ScopeConstraint] = []
            for constraint in scope:
                reason = _evaluate(constraint, now_tz)
                if reason is None:
                    surviving.append(constraint)
                    continue
                denials.append(
                    DenialRecord(
                        source_id=source_id,
                        reason=reason,
                        rule_name="scope-expired",
                    )
                )
            kept[source_id] = surviving
        return kept, denials


def _evaluate(constraint: ScopeConstraint, now: datetime) -> str | None:
    """Return a human-readable drop reason, or ``None`` if the constraint stays.

    Precedence: malformed > expired > not-yet-valid. Both slots are optional;
    when neither is set the constraint is unconditionally kept (Phase-1 shape).
    """
    if constraint.expires_at is not None:
        parsed = _parse_iso8601(constraint.expires_at)
        if parsed is None:
            return f"malformed expires_at: {constraint.expires_at!r}"
        if _normalise(parsed, now) <= now:
            return f"expires_at {constraint.expires_at} in the past"
    if constraint.valid_from is not None:
        parsed = _parse_iso8601(constraint.valid_from)
        if parsed is None:
            return f"malformed valid_from: {constraint.valid_from!r}"
        if _normalise(parsed, now) > now:
            return f"valid_from {constraint.valid_from} in the future"
    return None


__all__ = ["TemporalFilter"]
