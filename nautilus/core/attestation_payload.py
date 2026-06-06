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
    response_hash: str | None = None,
    hash_skipped: bool = False,
    source_response_hashes: dict[str, str] | None = None,
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
    if response_hash is not None:
        payload["response_hash"] = response_hash
    if source_response_hashes:
        # Per-source chain-of-custody claim (issue #19, design §5.7). Added
        # alongside the whole-response ``response_hash`` (kept for backward
        # compat so existing verifiers that read ``response_hash`` still work).
        # Covered by the JWT ``input_hash`` because the whole payload is the
        # signed ``input_facts`` (see ``Broker._sign``).
        #
        # COEXISTENCE WITH hash_skipped (DECISION, issue #19): in a MIXED request
        # that fans out to BOTH a non-deterministic source (llm) and one or more
        # deterministic sources, ``hash_skipped=True`` is set globally (the
        # *whole-response* hash is unverifiable because of the llm row) YET this
        # map still carries the deterministic sources' per-source digests. That
        # is intentional and is the entire point of per-source custody: a
        # verifier gets real integrity for postgres/etc. even when the merged
        # blob cannot be re-hashed. Read together: ``hash_skipped`` describes the
        # whole-response hash only; ``source_response_hashes`` enumerates exactly
        # which sources ARE covered (sources absent from the map — e.g. the llm —
        # are the unhashed ones). The two are NOT mutually exclusive by design.
        payload["source_response_hashes"] = dict(source_response_hashes)
    if hash_skipped:
        payload["hash_skipped"] = True
    return payload, version


def compute_response_hash(adapter_result: Any) -> str:
    """Return ``sha256:<hex>`` of the canonical JSON of ``adapter_result``.

    Wraps :func:`_stable_json` + :func:`_sha256` (the existing scheme at
    lines 58 + 69). AC-19.a.

    This is the *single* canonical hashing entry point. Per-source raw hashing
    (issue #19, design §5.7) reuses it verbatim via the
    :data:`compute_raw_response_hash` alias below so the "same canonical scheme"
    guarantee is structural, not documentary: there is exactly one
    implementation, whether hashing a whole merged response or one source's raw
    rows (``sort_keys=True`` → dict key order is irrelevant; byte-sensitive to
    content, AC-19.f).
    """
    return _sha256(adapter_result)


# Per-source raw hashing (issue #19) is byte-identical to the whole-response
# hash above — same canonical JSON + SHA-256. Aliased rather than duplicated so
# every caller shares one implementation (the "same canonical scheme" guarantee
# is enforced by identity, not by two docstrings agreeing).
compute_raw_response_hash = compute_response_hash


__all__ = ["build_payload", "compute_raw_response_hash", "compute_response_hash"]
