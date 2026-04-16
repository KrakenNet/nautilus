"""Synthesizer Protocol (design §3.6).

Merges per-source :class:`AdapterResult` objects into the
``{source_id: rows}`` shape used by :class:`BrokerResponse.data`.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from nautilus.core.models import AdapterResult


@runtime_checkable
class Synthesizer(Protocol):
    """Merges successful adapter results (design §3.6).

    Implementations MUST NOT raise on per-adapter failure: the broker
    pre-filters failed adapters into ``sources_errored`` before calling
    :meth:`merge`.
    """

    def merge(self, results: list[AdapterResult]) -> dict[str, list[dict[str, Any]]]:
        """Combine successful adapter results into the response payload.

        Args:
            results: Per-source successful :class:`AdapterResult` values
                (failed adapters have already been filtered out by the
                broker into ``sources_errored``).

        Returns:
            Mapping from ``source_id`` to the merged row list that will
            populate :attr:`BrokerResponse.data`.
        """
        ...


__all__ = ["Synthesizer"]
