"""Protocol definitions for Nautilus adapters and embedders."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .config import SourceConfig
    from .types import AdapterResult, IntentAnalysis, ScopeConstraint


@runtime_checkable
class Adapter(Protocol):
    """Protocol that all data-source adapters must satisfy."""

    source_type: ClassVar[str]

    async def connect(self, config: SourceConfig) -> None: ...

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict,
    ) -> AdapterResult: ...

    async def close(self) -> None: ...


@runtime_checkable
class Embedder(Protocol):
    """Protocol for text embedding providers."""

    async def embed(self, text: str) -> list[float]: ...
