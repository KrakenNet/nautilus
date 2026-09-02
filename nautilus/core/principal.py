"""Internal caller identity for the cumulative-exposure ledger (§4.15).

Cumulative exposure -- ``sources_visited``, ``data_types_seen``,
``pii_sources_accessed_list`` -- is what escalation packs and every
``session_exposure`` rule read. It accumulated per *declared* ``session_id``,
and the session id is chosen by the caller, so an agent that had accumulated
enough PII to trip escalation could declare a fresh session id and carry on
against a clean ledger. Omitting the session token did the same thing.

The fix is a key the caller does not choose. :func:`derive_principal_id`
folds the identity the caller was *authenticated* as into a stable
``principal:<digest>``, and the broker accumulates exposure under it as well as
under the declared session, so a fresh session id inherits the principal's
history.

**What is and is not in the key.** ``agent_id`` and the transport's
authenticated principal (the API key the request presented, or
``X-Forwarded-User`` under ``proxy_trust``) are in it: neither is settable by
the caller's payload. The peer address is used only when there is no
authenticated principal -- an unauthenticated deployment, or an in-library
caller -- because a network address is the *caller's* to change: putting it in
the key when a stronger signal exists would hand back the reset it closes (one
new egress IP, one clean ledger). Volatile signals still get recorded on the
principal record as ``observed_from`` so an operator can see the ledger's
provenance without them weakening it.
"""

from __future__ import annotations

import hashlib

# Sorted, so the digest does not depend on dict ordering, and prefixed per
# component so ("a", "bc") and ("ab", "c") cannot collide.
_SEP = "\x1f"


def ledger_identity(entry: object) -> str:
    """What a configured ``api.keys`` entry authenticates its holder as.

    ``api.keys[].principal`` when the entry names one, prefixed ``key`` and
    separated by :data:`_SEP` so a configured name cannot collide with a
    bare-string key's raw value or with a ``proxy_trust`` subject and share that
    caller's ledger. The separator is a control character on purpose: both of
    those arrive in an HTTP header value, which cannot carry one, so no
    credential a caller can present reaches this shape. Otherwise the secret
    itself -- the pre-1.0 derivation, kept because changing it for every entry
    would orphan every ledger a running deployment holds.

    A secret makes a poor identity for one reason only, and it is not the
    caller: the operator can replace it. Under the secret, the same caller
    before and after a rotation is two principals, so the replacement credential
    starts on a clean cumulative-exposure budget and is a stranger to the
    sessions its predecessor opened. ``principal`` is the part of a credential a
    rotation does not change.

    Duck-typed rather than typed against ``ApiKeyEntry``: this is core, the
    bare-string form has no attributes at all, and the transport passes whatever
    the operator wrote.
    """
    named = getattr(entry, "principal", None)
    if named:
        return f"key{_SEP}{named}"
    return entry if isinstance(entry, str) else str(getattr(entry, "key", ""))


def derive_principal_id(
    agent_id: str,
    *,
    auth_principal: str | None = None,
    peer: str | None = None,
) -> str:
    """Return the session-store key the caller's exposure accumulates under.

    ``auth_principal`` is the transport's authenticated caller. ``peer`` is the
    network address, used only as a fallback when there is no authenticated
    principal at all; see the module docstring for why it is not key material
    otherwise.
    """
    parts = [f"agent{_SEP}{agent_id}"]
    if auth_principal:
        parts.append(f"auth{_SEP}{auth_principal}")
    elif peer:
        parts.append(f"peer{_SEP}{peer}")
    digest = hashlib.sha256(_SEP.join(parts).encode("utf-8")).hexdigest()
    return f"principal:{digest[:32]}"


__all__ = ["derive_principal_id", "ledger_identity"]
