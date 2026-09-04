"""Adapter protocol, exception hierarchy, and scope-enforcement validators.

Implements design §3.5 (Adapter Protocol) and §6 (Scope Enforcement Strategy).

The ``_OPERATOR_ALLOWLIST`` set here is the runtime counterpart to the
``Literal[...]`` on ``ScopeConstraint.operator`` in ``nautilus/core/models.py``
(design §6.1). Drift between the two is caught by a dedicated drift-guard test
(Task 3.14).
"""

from __future__ import annotations

import asyncio
import functools
import ipaddress
import logging
import re
import socket
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, ClassVar, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# Either IP family; the SSRF guards test the same predicates on both.
_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

log = logging.getLogger(__name__)

if TYPE_CHECKING:
    import ssl

    from nautilus.adapters.schema import AdapterSchema
    from nautilus.config.models import MtlsAuth


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


def row_bytes(row: dict[str, Any]) -> int:
    """Roughly what ``row`` costs in the canonical JSON the caller receives.

    ``+ 1`` for the separator that will follow it. Deliberately the same
    estimate the MCP transport bounds a tool result with, so a source trimmed
    at one layer is trimmed the same way at the next.
    """
    import json

    return len(json.dumps(row, default=str)) + 1


def bounded_rows(
    rows: list[dict[str, Any]], max_bytes: int | None
) -> tuple[list[dict[str, Any]], bool]:
    """Return ``rows`` cut to ``max_bytes``, and whether anything was dropped.

    Whole rows only: half a row is not a row. Always keeps at least one, so a
    single oversized row comes back marked truncated rather than as an empty
    result the caller cannot tell from "nothing matched".
    """
    if max_bytes is None:
        return rows, False
    used = 0
    for index, row in enumerate(rows):
        used += row_bytes(row)
        if used > max_bytes and index > 0:
            return rows[:index], True
    return rows, False


async def resolve_base_url(base_url: str, adapter: str) -> tuple[str, list[_IPAddress]]:
    """Return ``base_url``'s host and every address it currently resolves to.

    The single seam both SSRF guards run on -- :func:`RestAdapter's
    <nautilus.adapters.rest._reject_unroutable_base_url>` (shared with
    ``ServiceNowAdapter``) and :func:`LLMAdapter's
    <nautilus.adapters.llm._reject_unroutable_base_url>`. They refuse different
    address classes on purpose, so the *policy* stays in each adapter; parsing
    and name resolution live here so there is one place to audit and one place
    a fix lands.

    An IP literal resolves to itself with no lookup. A name goes through the
    running loop's ``getaddrinfo``, which runs in a thread, so a slow resolver
    does not block the event loop; the caller's own deadline
    (``SourceConfig.timeout_s``, applied by the broker around ``connect()``)
    bounds how long it may take.

    **A name that does not resolve returns an empty list, not an error.** A
    host with no address reaches nothing, so refusing here would buy no
    security and would only replace the driver's own DNS message with ours.

    **What this cannot do.** The answer is the resolver's answer *now*; httpx,
    asyncpg and every other driver resolve again when they dial. A resolver
    that returns a routable address here and a private one microseconds later
    (DNS rebinding, a short-TTL record, a round-robin set that changes) is not
    caught. This is a config-hygiene control with a genuine TOCTOU window, not
    a dial-time pin -- see ``docs/reference/errors/adapters.md``.

    Raises:
        ScopeEnforcementError: ``base_url`` parses with no host.
    """
    host = urlsplit(base_url).hostname
    if not host:
        # The value is withheld deliberately: a malformed connection string is
        # exactly the shape that still carries userinfo
        # (``http://user:pw@``), and this message reaches the audit trail.
        raise ScopeEnforcementError(
            f"{adapter} requires a non-empty host in base_url "
            f"(scheme={urlsplit(base_url).scheme!r}; the value is withheld "
            f"because a connection string can carry credentials)"
        )
    try:
        addresses = [ipaddress.ip_address(host)]  # a literal resolves to itself
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, None, type=socket.SOCK_STREAM
            )
        except (OSError, UnicodeError):
            addresses = []
        else:
            addresses = [ipaddress.ip_address(str(info[4][0])) for info in infos]
    # The lookup is the thing that decides whether the config works, and it
    # happens inside a guard the operator never sees run: a ``rest`` source
    # that started being refused after this stopped testing IP literals had no
    # line anywhere saying which address its name answers with. Emitted for
    # literals too, so "the guard did resolve, and this is what it saw" is one
    # grep rather than two cases.
    log.debug(
        "%s SSRF guard: base_url host %s resolves to %s",
        adapter,
        host,
        [str(address) for address in addresses] if addresses else "no address",
    )
    return host, addresses


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


def quote_table(table: str) -> str:
    """Quote a possibly schema-qualified table name.

    ``schema.table`` renders as ``"schema"."table"``; a bare name renders as
    ``"table"``. Each segment goes through :func:`quote_identifier`, so the
    same regex guard applies to both.

    Callers used to do ``quote_identifier(table.split(".")[-1])``, which
    silently discarded the schema: a source declaring
    ``table: restricted.customers`` emitted ``SELECT * FROM "customers"`` and
    Postgres resolved it through ``search_path``, reading a different table
    than the config named.
    """
    parts = table.split(".")
    if len(parts) > 2:
        raise ScopeEnforcementError(f"table name {table!r} has more than one schema qualifier")
    return ".".join(quote_identifier(part) for part in parts)


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


def mtls_context(auth: MtlsAuth, source_id: str) -> ssl.SSLContext:
    """Build the TLS context a source's ``auth: {type: mtls}`` block describes.

    Both the Elasticsearch and Neo4j adapters used to accept an ``mtls`` block
    and drop the certificate: Elasticsearch forwarded ``ca_path`` alone (and
    only when it was set), Neo4j discarded the block entirely with a comment
    saying the certificate belongs on the URI. Either way the operator saw no
    error and got a connection that presents no client certificate — a
    credential silently downgraded to none.

    Raises:
        AdapterError: if the certificate, key or CA cannot be loaded. A path
            that does not resolve is a configuration error, not a reason to
            connect anonymously.
    """
    import ssl

    context = ssl.create_default_context(cafile=auth.ca_path)
    try:
        context.load_cert_chain(certfile=auth.cert_path, keyfile=auth.key_path)
    except (OSError, ssl.SSLError) as exc:
        raise AdapterError(
            f"source '{source_id}' declares mTLS but its client certificate could "
            f"not be loaded (cert_path={auth.cert_path!r}, key_path={auth.key_path!r}): {exc}"
        ) from exc
    return context


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


# Bound to a TypeVar, not spelled out as a ``Callable[...]``: a ``Callable``
# parameter list is positional-only, so a decorated ``execute`` no longer
# matched the :class:`Adapter` protocol (which names ``intent`` / ``scope`` /
# ``context``) and every wrapped adapter dropped out of ``type[Adapter]``.
type _ExecuteBody = Callable[..., Awaitable["AdapterResult"]]


def wrap_execute[F: _ExecuteBody](fn: F) -> F:
    """Re-raise a backend driver's own exceptions from ``execute`` as ``AdapterError``.

    :class:`Adapter` documents ``AdapterError`` as the only non-scope failure
    ``execute`` raises, and third-party adapters are written against that
    contract. Most in-tree adapters let the raw driver exception escape instead
    -- ``asyncpg.PostgresSyntaxError``, ``elasticsearch.ApiException`` -- which
    the broker still records as a per-source error, but under the driver's type
    name and with no indication of which source produced it.

    ``ScopeEnforcementError`` (and any other ``AdapterError``) passes through
    untouched: the broker distinguishes a refused constraint from an
    infrastructure failure.
    """

    @functools.wraps(fn)
    async def _wrapped(
        self: Any,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        try:
            return await fn(self, intent, scope, context)
        except AdapterError:
            raise
        except Exception as exc:
            config = getattr(self, "_config", None)
            source_id = getattr(config, "id", "?")
            # ``httpx.ReadTimeout()`` and friends carry no text, and appending
            # an empty ``{exc}`` produced "... ReadTimeout: " -- a message
            # ending in a colon and nothing, which was the whole thing an
            # operator saw for a dead backend. Drop the tail when there is
            # nothing to put after it.
            detail = str(exc)
            raise AdapterError(
                f"{type(self).__name__}: execute failed for source '{source_id}': "
                f"{type(exc).__name__}" + (f": {detail}" if detail else "")
            ) from exc

    return cast("F", _wrapped)


__all__ = [
    "mtls_context",
    "SESSION_TOKEN_HEADER",
    "Adapter",
    "AdapterError",
    "EmbeddingUnavailableError",
    "ScopeEnforcementError",
    "quote_identifier",
    "resolve_base_url",
    "quote_table",
    "render_field",
    "session_token_headers",
    "validate_field",
    "validate_operator",
    "wrap_execute",
]
