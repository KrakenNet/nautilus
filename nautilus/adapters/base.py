"""Adapter protocol, exception hierarchy, and scope-enforcement validators.

Implements design §3.5 (Adapter Protocol) and §6 (Scope Enforcement Strategy).

The ``_OPERATOR_ALLOWLIST`` set here is the runtime counterpart to the
``Literal[...]`` on ``ScopeConstraint.operator`` in ``nautilus/core/models.py``
(design §6.1). Drift between the two is caught by a dedicated drift-guard test
(Task 3.14).
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Protocol, runtime_checkable

from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint


class AdapterError(Exception):
    """Base class for all adapter-layer failures (design §3.5 invariants)."""


class ScopeEnforcementError(AdapterError):
    """Raised when a scope constraint violates the operator/field allowlist.

    Per design §6.3, callers (the broker) convert this into a
    ``sources_errored`` entry rather than propagating to the agent.
    """


class EmbeddingUnavailableError(AdapterError):
    """Raised when no embedder can produce a vector for a pgvector request.

    Design §10 error table: surfaces as a ``sources_errored`` entry rather than
    propagating to the agent. Lives here (rather than in ``embedder.py``) so the
    full adapter exception hierarchy is defined in a single module.
    """


# Runtime operator allowlist — keep in sync with the ``Literal[...]`` on
# ``ScopeConstraint.operator`` in ``nautilus/core/models.py`` (design §6.1).
_OPERATOR_ALLOWLIST: frozenset[str] = frozenset(
    {
        "=",
        "!=",
        "IN",
        "NOT IN",
        "<",
        ">",
        "<=",
        ">=",
        "LIKE",
        "BETWEEN",
        "IS NULL",
    }
)


# Field-identifier regex from design §6.2.
_FIELD_PATTERN: re.Pattern[str] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")


def validate_operator(op: str) -> None:
    """Validate ``op`` against the design §6.1 operator allowlist.

    Raises ``ScopeEnforcementError`` when the operator is not on the allowlist.
    """
    if op not in _OPERATOR_ALLOWLIST:
        raise ScopeEnforcementError(
            f"Operator '{op}' not in allowlist: {sorted(_OPERATOR_ALLOWLIST)}"
        )


def validate_field(f: str) -> None:
    """Validate ``f`` matches the design §6.2 field-identifier regex.

    Accepts a simple identifier (``col``) or a single dotted pair
    (``json_col.key``) for JSONB access. Anything else raises
    ``ScopeEnforcementError``.
    """
    if not _FIELD_PATTERN.match(f):
        raise ScopeEnforcementError(f"Invalid field identifier '{f}'")


def quote_identifier(ident: str) -> str:
    """Quote a SQL identifier safely (double-quote, doubled-quote escape).

    ``asyncpg`` does not expose a public identifier-quoting helper; this is the
    vetted one-liner used throughout the adapter layer (NFR-4, design §6.2,
    §7.3). ``ident`` is first run through :func:`validate_field` so an attacker
    cannot smuggle SQL through a crafted identifier — the regex pins the first
    character to ``[A-Za-z_]`` and forbids everything outside ``[A-Za-z0-9_]``
    (plus a single dot for JSONB access, which callers split before quoting).

    Raises ``ScopeEnforcementError`` when ``ident`` fails the regex check
    (e.g. leading digit ``"1bad"`` or embedded quote ``'x"; DROP TABLE ...``).
    """
    validate_field(ident)
    # Double any embedded quote for belt-and-braces defense; the regex already
    # forbids ``"`` so ``replace`` is a no-op on validated inputs. Kept so the
    # helper remains correct if :func:`validate_field` ever loosens.
    return '"' + ident.replace('"', '""') + '"'


def render_field(field: str) -> str:
    """Render a scope field reference as SQL per design §6.2.

    Plain identifier ``col`` → ``"col"``.
    Dotted identifier ``jsonb_col.key`` → ``"jsonb_col"->>'key'`` (JSONB text
    accessor, NFR-4).

    ``field`` is validated in full (``parent.child`` or plain), and each
    segment is re-validated before quoting so a dotted input cannot introduce
    a segment that individually fails the regex. The JSONB key literal is
    wrapped in single quotes; the regex-cleaned key cannot contain a quote.
    """
    validate_field(field)
    if "." in field:
        parent, child = field.split(".", 1)
        # Child is regex-clean (``validate_field`` covers both halves); no
        # quoting beyond single-quoting the literal.
        return f"{quote_identifier(parent)}->>'{child}'"
    return quote_identifier(field)


@runtime_checkable
class Adapter(Protocol):
    """Adapter Protocol mirroring design §3.5 verbatim."""

    source_type: ClassVar[str]

    async def connect(self, config: SourceConfig) -> None:
        """Initialise adapter state (pools, clients) for ``config``.

        Args:
            config: The source config the broker resolved this adapter for.

        Raises:
            AdapterError: On any infrastructure / connectivity failure;
                the broker converts these into ``sources_errored`` entries.
        """
        ...

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Run one query against the backing source.

        Args:
            intent: Structured intent produced by the analyzer.
            scope: Router-issued scope constraints for this source.
            context: Per-request context (purpose, clearance, embedding
                override, etc.).

        Returns:
            An :class:`AdapterResult` with ``rows`` populated on success
            or ``error`` populated on runtime failure.

        Raises:
            ScopeEnforcementError: If ``scope`` violates the operator or
                field-identifier allowlist (design §6).
            AdapterError: On any non-scope runtime failure.
        """
        ...

    async def close(self) -> None:
        """Release adapter resources; MUST be idempotent (FR-17, AC-8.6)."""
        ...


__all__ = [
    "Adapter",
    "AdapterError",
    "EmbeddingUnavailableError",
    "ScopeEnforcementError",
    "quote_identifier",
    "render_field",
    "validate_field",
    "validate_operator",
]
