"""Source registry.

Thin wrapper around ``list[SourceConfig]`` exposing id-based lookup plus
iteration. Enforces id uniqueness at construction time per design §3.2
(AC-1.3, AC-1.4).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from nautilus.config.loader import ConfigError
from nautilus.config.models import SourceConfig


class SourceRegistry:
    """Registry of :class:`SourceConfig` entries keyed by ``id``.

    Construction raises :class:`ConfigError` on duplicate ids so downstream
    code may assume a 1:1 mapping from ``source_id`` to config.
    """

    def __init__(self, sources: Iterable[SourceConfig]) -> None:
        source_list = list(sources)
        by_id: dict[str, SourceConfig] = {}
        for source in source_list:
            if source.id in by_id:
                raise ConfigError(f"Duplicate source id='{source.id}'")
            by_id[source.id] = source
        self._sources: list[SourceConfig] = source_list
        self._by_id: dict[str, SourceConfig] = by_id

    @property
    def sources(self) -> list[SourceConfig]:
        """Return a shallow copy of the registered source configs."""
        return list(self._sources)

    def get(self, source_id: str) -> SourceConfig:
        """Return the config for ``source_id`` or raise :class:`KeyError`."""
        return self._by_id[source_id]

    def __iter__(self) -> Iterator[SourceConfig]:
        return iter(self._sources)

    def __len__(self) -> int:
        return len(self._sources)
