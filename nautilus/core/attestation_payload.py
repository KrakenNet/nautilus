"""Nautilus attestation payload builder (design §9.3, §3.10).

Isolated from :mod:`nautilus.core.broker` so hash determinism (NFR-14)
can be unit-tested without spinning the full broker pipeline.

The payload shape mirrors design §9.3:

.. code-block:: json

    {
      "iss": "nautilus",
      "request_id": "uuid",
      "agent_id": "agent-alpha",
      "sources_queried": ["nvd_db", "internal_vulns"],
      "rule_trace_hash": "sha256:...",
      "scope_hash": "sha256:..."
    }

``iat`` is deliberately *not* emitted here — the Fathom
``AttestationService.sign()`` stamps its own ``iat`` on the outer JWT
claim set; embedding a second timestamp here would break determinism.

Hashes are derived via canonical JSON (``sort_keys=True`` and
separators ``(",", ":")``) so structurally-identical inputs with
different dict ordering produce identical digests.

Two canonicalization versions exist (design §3.10, D-7, FR-19):

- **v1 (frozen)** — Phase 1 shape: the ``scope_constraints`` payload is
  hashed as-received. This path is preserved bit-for-bit so Phase 1
  tokens remain verifiable under the Phase 2 verifier (NFR-6). When
  the caller supplies the broker-internal
  ``dict[source_id, list[ScopeConstraint]]`` shape, it is flattened to
  the Phase-1 4-key list ``[{source_id, field, operator, value}, ...]``
  using the legacy iteration order (``for bucket in .values(): for c in
  bucket``) so both call paths produce identical bytes.
- **v2 (conditional)** — emitted *only* when at least one constraint
  carries a non-empty ``expires_at`` or ``valid_from`` slot. v2 hashes a
  6-tuple-shaped list ``[{source_id, field, operator, value,
  expires_at, valid_from}, ...]`` sorted by ``(source_id, field,
  operator)``; unset temporal slots serialize as the empty string.

The version discriminator is returned alongside the payload so callers
(notably :class:`~nautilus.core.broker.Broker`) can stamp it into
:attr:`AuditEntry.scope_hash_version`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any, Literal

_SHA256_PREFIX = "sha256:"


def _stable_json(value: Any) -> str:
    """Canonical JSON encoding used for deterministic hashing.

    - ``sort_keys=True`` — dict key order is irrelevant.
    - ``separators=(",", ":")`` — no incidental whitespace.
    - ``default=str`` — falls back to ``str(obj)`` for non-JSON-native
      values (e.g. ``datetime``, ``Decimal``) so hashing never raises.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(value: Any) -> str:
    """Return ``sha256:<hex>`` of the canonical JSON encoding of ``value``."""
    digest = hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()
    return f"{_SHA256_PREFIX}{digest}"


def _get_slot(item: Any, name: str) -> Any:
    """Read ``name`` from a dict-shaped OR attribute-shaped constraint.

    v2 detection accepts both the broker's flattened ``dict`` payload and
    raw :class:`ScopeConstraint` instances (e.g. when callers skip the
    flattening step in unit tests).
    """
    if isinstance(item, dict):
        return item.get(name)  # type: ignore[no-any-return]
    return getattr(item, name, None)


def _flat_iter(constraints: Any) -> Iterable[Any]:
    """Yield constraint items regardless of outer shape (dict / list / tuple)."""
    if isinstance(constraints, dict):
        for bucket in constraints.values():  # type: ignore[misc]
            if isinstance(bucket, (list, tuple)):
                yield from bucket  # type: ignore[misc]
            else:
                yield bucket
    elif isinstance(constraints, (list, tuple)):
        yield from constraints  # type: ignore[misc]


def _has_temporal_slot(constraints: Any) -> bool:
    """True iff ``constraints`` carries any non-empty temporal slot.

    Accepts both the broker's list-of-dicts flattened shape and a
    ``dict[str, list[ScopeConstraint]]`` internal shape. Empty strings
    and ``None`` both count as unset so v2 only triggers when a caller
    actually populated a window (D-7 conditional v2).
    """
    for item in _flat_iter(constraints):
        if _get_slot(item, "expires_at") or _get_slot(item, "valid_from"):
            return True
    return False


def _has_cost_cap_context(request: Any, response: Any) -> bool:
    """True iff a cost-cap summary should be emitted on the v2 payload.

    Mirrors the design's Cross-Cutting Concerns block: fire when the
    response flags a cap breach, OR when any queried source declared
    non-None effective caps that contributed to an enforcement decision
    (Task 20 / AC-2.12). The second branch picks up
    ``effective_caps_per_source`` — a dict duck-typed onto the response
    shim by :meth:`nautilus.core.broker.Broker._sign`. ``None`` response
    short-circuits to False so legacy callers (back-compat fixtures,
    NFR-ATT-V2-FROZEN) keep byte-identical output.
    """
    if response is None:
        return False
    if getattr(response, "cap_breached", None):
        return True
    return bool(getattr(response, "effective_caps_per_source", None))


def _has_fact_set_hash(request: Any) -> bool:
    """True iff the incoming request carries a non-empty ``fact_set_hash``."""
    return bool(request is not None and getattr(request, "fact_set_hash", None))


def _has_session_signatures(response: Any) -> bool:
    """True iff the response carries non-empty ``source_session_signatures``."""
    return bool(response is not None and getattr(response, "source_session_signatures", None))


def _v1_payload(constraints: Any) -> Any:
    """Return the Phase-1 scope payload to hash for v1 (FROZEN).

    - When ``constraints`` is the broker-internal
      ``dict[source_id, list[ScopeConstraint]]`` shape, flatten to the
      legacy 4-key list in the legacy iteration order (``.values()`` →
      per-bucket) so bytes match what the pre-Task-1.12 ``_sign`` path
      emitted.
    - Otherwise the payload is hashed as-received — this is the exact
      Phase-1 behavior (``list[dict]`` or any other JSON-able shape).
    """
    if isinstance(constraints, dict):
        rows: list[dict[str, Any]] = []
        for bucket in constraints.values():  # type: ignore[misc]
            items: list[Any] = (
                [x for x in bucket]  # type: ignore[misc]
                if isinstance(bucket, (list, tuple))
                else [bucket]
            )
            for item in items:
                rows.append(
                    {
                        "source_id": _get_slot(item, "source_id"),
                        "field": _get_slot(item, "field"),
                        "operator": _get_slot(item, "operator"),
                        "value": _get_slot(item, "value"),
                    }
                )
        return rows
    return constraints


def _v2_canonical(constraints: Any) -> list[dict[str, Any]]:
    """Build the v2-canonical 6-tuple list, sorted by (source_id, field, operator).

    Empty strings stand in for unset ``expires_at`` / ``valid_from`` so
    every row is uniformly 6 keys wide (design §3.10). The caller may
    pass either the broker's flattened list or the internal
    ``dict[source_id, list[ScopeConstraint]]`` shape.
    """
    rows: list[dict[str, Any]] = []
    for item in _flat_iter(constraints):
        rows.append(
            {
                "source_id": _get_slot(item, "source_id"),
                "field": _get_slot(item, "field"),
                "operator": _get_slot(item, "operator"),
                "value": _get_slot(item, "value"),
                "expires_at": _get_slot(item, "expires_at") or "",
                "valid_from": _get_slot(item, "valid_from") or "",
            }
        )
    rows.sort(key=lambda r: (str(r["source_id"]), str(r["field"]), str(r["operator"])))
    return rows


def build_payload(
    request_id: str,
    agent_id: str,
    sources_queried: list[str],
    scope_constraints: Any,
    rule_trace: Any,
    *,
    request: Any | None = None,
    response: Any | None = None,
) -> tuple[dict[str, Any], Literal["v1", "v2"]]:
    """Build the Nautilus attestation payload + its scope-hash version.

    Parameters are positional-friendly so callers can mirror the
    arguments they would otherwise stuff into an inline dict.

    ``scope_constraints`` may be a ``list[dict]`` (already-flattened
    scope payload), a ``dict[str, list[ScopeConstraint]]`` (broker
    internal shape) or a raw ``list[ScopeConstraint]``.

    ``rule_trace`` is typically a ``list[str]`` but any JSON-able value
    is accepted for flexibility.

    Version rule (D-7, FR-19): emits ``"v2"`` when at least one
    constraint carries a non-empty ``expires_at`` or ``valid_from`` slot;
    otherwise ``"v1"`` with the frozen Phase-1 canonicalization (the
    payload is hashed as-received when pre-flattened, or flattened to
    the Phase-1 4-key list when passed as the internal dict shape —
    either way bit-for-bit reproducible with Phase-1 output, NFR-6).

    ``request`` / ``response`` are optional keyword-only handles on the
    surrounding :class:`BrokerRequest` / :class:`BrokerResponse` (passed
    by attribute name to avoid a circular import). When supplied and
    populated, they opt the payload into three conditional v2 extensions
    (design Cross-Cutting Concerns block): ``cost_cap_context``,
    ``fact_set_hash``, and ``session_signatures``. When either is
    ``None`` (or when every ``_has_*()`` guard returns False), the
    emitted payload is byte-identical to the pre-spec output — the
    NFR-ATT-V2-FROZEN guarantee.
    """
    if _has_temporal_slot(scope_constraints):
        scope_hash = _sha256(_v2_canonical(scope_constraints))
        version: Literal["v1", "v2"] = "v2"
    else:
        scope_hash = _sha256(_v1_payload(scope_constraints))
        version = "v1"
    payload: dict[str, Any] = {
        "iss": "nautilus",
        "request_id": request_id,
        "agent_id": agent_id,
        "sources_queried": list(sources_queried),
        "scope_hash": scope_hash,
        "rule_trace_hash": _sha256(rule_trace),
    }
    # Conditional-on-presence extensions (design Cross-Cutting Concerns
    # Summary). Each guard returns False when its input is None, so
    # legacy 5-positional-arg callers keep byte-identical output.
    if _has_fact_set_hash(request) and request is not None:
        payload["fact_set_hash"] = request.fact_set_hash
    if _has_session_signatures(response) and response is not None:
        payload["session_signatures"] = response.source_session_signatures
    if _has_cost_cap_context(request, response) and response is not None:
        # Task 20 / AC-2.12 — enrich the cost-cap context with the
        # per-source effective caps that applied to this request (if any).
        # The ``effective_caps_per_source`` attribute is duck-typed onto
        # the response shim by :meth:`Broker._sign`; when absent the block
        # collapses to the minimal Task-9 shape so fixtures that only set
        # ``cap_breached`` stay backward-compatible.
        cost_cap_context: dict[str, Any] = {
            "cap_breached": bool(getattr(response, "cap_breached", False))
        }
        effective = getattr(response, "effective_caps_per_source", None)
        if effective:
            cost_cap_context["effective_caps_per_source"] = dict(effective)
        payload["cost_cap_context"] = cost_cap_context
    return payload, version


__all__ = ["build_payload"]
