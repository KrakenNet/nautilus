"""Protocol definitions for Nautilus adapters and embedders."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .config import SourceConfig
    from .schema import AdapterSchema
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

    async def get_schema(self) -> AdapterSchema:
        """Return the adapter's schema fingerprint surface (AC-21.a).

        Default raises NotImplementedError until per-adapter impl lands
        (task-006).  Shared.md line 315-322.
        """
        raise NotImplementedError("AC-21.b: this adapter must implement get_schema() (task-006)")


@runtime_checkable
class Embedder(Protocol):
    """Protocol for text embedding providers."""

    async def embed(self, text: str) -> list[float]: ...
