"""Adapter protocol, exception hierarchy, and scope-enforcement validators.

Implements design §3.5 (Adapter Protocol) and §6 (Scope Enforcement Strategy).

The ``_OPERATOR_ALLOWLIST`` set here is the runtime counterpart to the
``Literal[...]`` on ``ScopeConstraint.operator`` in ``nautilus/core/models.py``
(design §6.1). Drift between the two is caught by a dedicated drift-guard test
(Task 3.14).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar, Protocol, runtime_checkable

from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

if TYPE_CHECKING:
    from nautilus.adapters.schema import AdapterSchema


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


SESSION_TOKEN_HEADER = "X-Nautilus-Session-Token"
"""HTTP header carrying the broker-issued session-provenance JWS (#18, AC-18.b).

Mirrors ``nautilus.transport.auth._SESSION_TOKEN_HEADER`` — duplicated here so
the adapter layer never imports the transport layer.
"""


def session_token_headers(context: dict[str, Any]) -> dict[str, str] | None:
    """Build the outbound session-token header from request ``context`` (AC-18.b).

    The broker injects ``context["session_token"]`` when session tokens are
    enabled (#18); HTTP-family adapters forward it so downstream services can
    correlate calls to their originating session. Returns ``None`` when no
    token is present — httpx treats ``headers=None`` as "no extra headers".
    """
    token = context.get("session_token")
    if isinstance(token, str) and token:
        return {SESSION_TOKEN_HEADER: token}
    return None


@runtime_checkable
class Adapter(Protocol):
    """Adapter Protocol mirroring design §3.5 verbatim.

    Capability contract (design §3.5, AC-19.g, issue #56 review): a
    non-deterministic adapter — one whose ``rows`` are not byte-reproducible
    across identical requests, e.g. an LLM — MUST expose a class attribute
    ``capabilities: ClassVar[frozenset[str]]`` containing ``"non_deterministic"``
    (see :class:`~nautilus.adapters.llm.LLMAdapter`). The broker then excludes it
    from per-source response hashing and signs ``hash_skipped=True`` instead;
    hashing a non-reproducible source would sign a digest that can never be
    re-verified. Deterministic adapters omit ``capabilities`` entirely and
    ``Broker._is_non_deterministic`` defaults the missing attribute to
    deterministic. It is intentionally NOT a typed Protocol member: a
    ``@runtime_checkable`` data member is required, not optional, which would
    break ``isinstance`` and ``type[Adapter]`` assignability for every
    deterministic adapter that legitimately omits it — so the contract is
    documented here instead.
    """

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
            or ``error`` populated on runtime failure. The per-source
            chain-of-custody digest (issue #19, design §5.7 Weakness 7) is
            computed centrally and exclusively by the broker over ``rows`` at
            the pre-synthesis boundary; an adapter never supplies its own digest
            (there is no ``response_hash`` field on :class:`AdapterResult`) so a
            malicious or buggy adapter cannot inject an arbitrary hash into the
            signed attestation (issue #56 review). Non-deterministic adapters
            (``capabilities`` containing ``"non_deterministic"``, e.g. the LLM
            adapter) are excluded from hashing entirely so the broker signs
            ``hash_skipped=True`` instead (AC-19.g).

        Raises:
            ScopeEnforcementError: If ``scope`` violates the operator or
                field-identifier allowlist (design §6).
            AdapterError: On any non-scope runtime failure.
        """
        ...

    async def close(self) -> None:
        """Release adapter resources; MUST be idempotent (FR-17, AC-8.6)."""
        ...

    async def get_schema(self) -> AdapterSchema:
        """Return the adapter's schema fingerprint surface.

        Default implementation raises :exc:`NotImplementedError`; concrete
        adapters override this in task-006.  Per-adapter impls land later so
        registration succeeds at import-time but fails at runtime if called
        before the adapter implements it (AC-21.b; shared.md line 315-322).

        Raises:
            NotImplementedError: Until the per-adapter implementation lands
                (task-006).
        """
        raise NotImplementedError("AC-21.b: this adapter must implement get_schema() (task-006)")


__all__ = [
    "SESSION_TOKEN_HEADER",
    "Adapter",
    "AdapterError",
    "EmbeddingUnavailableError",
    "ScopeEnforcementError",
    "quote_identifier",
    "render_field",
    "session_token_headers",
    "validate_field",
    "validate_operator",
]
