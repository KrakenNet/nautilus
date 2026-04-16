"""Embedder Protocol and shipped ``NoopEmbedder`` default.

Implements design §3.10 and §7.2 (embedder resolution precedence).

The default ``NoopEmbedder(strict=True)`` raises ``EmbeddingUnavailableError``
rather than silently returning a zero vector — the broker converts that error
into a ``sources_errored`` entry (design §10). Users who genuinely want a
no-op vector (e.g. unit tests against pgvector without a real model) can
opt in with ``NoopEmbedder(strict=False, dimension=N)``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

# ``EmbeddingUnavailableError`` lives in ``nautilus.adapters.base`` alongside the
# rest of the adapter exception hierarchy (Task 2.2). Re-exported here for
# backward compatibility with existing imports.
from nautilus.adapters.base import EmbeddingUnavailableError


@runtime_checkable
class Embedder(Protocol):
    """Embedder Protocol mirroring design §3.10 verbatim."""

    def embed(self, text: str) -> list[float]:
        """Return a dense-vector embedding of ``text``.

        Args:
            text: String to embed (typically the raw intent or a
                pre-processed variant).

        Returns:
            Vector of ``float`` whose dimensionality matches the target
            pgvector column.

        Raises:
            EmbeddingUnavailableError: If the embedder cannot produce a
                vector (e.g. no model configured); the broker converts
                this into a ``sources_errored`` entry (design §10).
        """
        ...


class NoopEmbedder:
    """Default embedder shipped by Nautilus (design §3.10).

    Strict mode (the default) refuses to produce silent garbage: ``embed()``
    always raises ``EmbeddingUnavailableError``. Non-strict mode returns a
    zero vector of ``dimension`` elements — useful only for smoke tests.
    """

    def __init__(self, strict: bool = True, dimension: int = 1536) -> None:
        self._strict: bool = strict
        self._dimension: int = dimension

    def embed(self, text: str) -> list[float]:
        """Return a zero vector or raise, depending on ``strict``.

        The ``text`` argument is intentionally unused in both branches —
        ``NoopEmbedder`` exists to prove the Protocol surface and to serve as
        an explicit ``"not configured"`` sentinel. Real embedders (sentence-
        transformers, OpenAI, etc.) land in Phase 2.
        """
        del text  # Noop by design: never inspects the input.
        if self._strict:
            raise EmbeddingUnavailableError(
                "NoopEmbedder(strict=True) cannot produce embeddings. "
                "Pass context['embedding']: list[float] at request time, "
                "configure a per-source embedder, or construct the broker "
                "with a non-strict embedder."
            )
        return [0.0] * self._dimension


__all__ = [
    "Embedder",
    "EmbeddingUnavailableError",
    "NoopEmbedder",
]
