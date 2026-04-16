"""Agent registry.

Thin wrapper around ``dict[str, AgentRecord]`` exposing id-based lookup
plus iteration. Raises :class:`UnknownAgentError` when an agent id is
not declared in ``nautilus.yaml`` (design §3.5, FR-9, AC-4.2).

Phase 1 YAML documents without an ``agents:`` section resolve to an
empty registry to preserve backwards compatibility (AC-5.3 precedent,
NFR-5).
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping

from nautilus.config.models import AgentRecord


class UnknownAgentError(Exception):
    """Raised when :meth:`AgentRegistry.get` is asked for an unregistered id."""


class AgentRegistry:
    """Registry of :class:`AgentRecord` entries keyed by ``id``.

    The registry is read-only from the caller's perspective: entries are
    supplied at construction and never mutated. The input mapping is
    shallow-copied so later edits by the caller do not leak into the
    registry.
    """

    def __init__(self, agents: Mapping[str, AgentRecord]) -> None:
        self._agents: dict[str, AgentRecord] = dict(agents)

    def get(self, agent_id: str) -> AgentRecord:
        """Return the :class:`AgentRecord` for ``agent_id``.

        Raises :class:`UnknownAgentError` if ``agent_id`` is not registered.
        """
        try:
            return self._agents[agent_id]
        except KeyError as exc:
            raise UnknownAgentError(f"Unknown agent id='{agent_id}'") from exc

    def __iter__(self) -> Iterator[AgentRecord]:
        return iter(self._agents.values())

    def __len__(self) -> int:
        return len(self._agents)


__all__ = ["AgentRegistry", "UnknownAgentError"]
