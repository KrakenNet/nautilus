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

# Prefixed per component, so ("a", "bc") and ("ab", "c") cannot collide --
# which holds only while no component can contain the separator itself; see
# :func:`derive_principal_id`.
_SEP = "\x1f"


def ledger_identity(entry: object) -> str:
    """What a configured ``api.keys`` entry authenticates its holder as.

    ``api.keys[].principal`` when the entry names one, prefixed ``key`` and
    separated by :data:`_SEP` so a configured name cannot collide with a
    bare-string key's raw value or with a ``proxy_trust`` subject and share that
    caller's ledger. A bare-string key cannot reach this shape: the value is
    matched against the configured list, so it is the operator's, not the
    caller's. A ``proxy_trust`` subject is a raw ``X-Forwarded-User``, and h11
    does pass U+001F through in a header value (measured, not assumed), so what
    keeps the two apart is that ``api.auth.mode`` picks one producer or the
    other for the whole deployment -- a subject can reach the shape, but in a
    deployment where no ``api.keys[].principal`` occupies it. Otherwise the secret
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


def _refuse(field: str) -> None:
    """Refuse ``field`` for carrying the component separator.

    The value is never quoted back: for a credential that names no
    ``principal``, ``auth_principal`` *is* the API key, and this message
    reaches an HTTP 400 body and the process log.
    """
    raise ValueError(
        f"{field} contains U+001F, which separates the components of the "
        f"cumulative-exposure ledger's key. A value carrying one can spell out "
        f"another caller's components inside its own and accumulate onto that "
        f"caller's ledger, so it is refused."
    )


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

    Raises:
        ValueError: when a component carries :data:`_SEP` anywhere the
            separator is not structure. The separator is the only thing that
            tells one component from the next, so a component free to carry it
            is free to declare components that were never supplied: with no
            authenticated principal and no peer,
            ``agent_id="analyst\\x1fauth\\x1fkey\\x1fsvc"`` hashes to exactly
            what ``agent_id="analyst"`` under the authenticated principal
            ``key\\x1fsvc`` hashes to, and the forger accumulates onto that
            caller's cumulative-exposure ledger. Since ``api.keys[].principal``
            is a name an operator writes in ``nautilus.yaml`` rather than a
            secret, forging it takes no credential at all.

            Refused rather than escaped, deliberately: escaping would change
            the digest for every input that is valid today and orphan every
            ledger a running deployment holds. It reaches a REST caller as
            ``400`` (``_handle_request`` maps ``ValueError``) and an MCP caller
            as a tool error; no agent id or socket address legitimately carries
            a control character, so nothing that worked stops working.
    """
    for field, value in (("agent_id", agent_id), ("peer", peer)):
        if value and _SEP in value:
            _refuse(field)
    if auth_principal and _SEP in auth_principal:
        # One separator, in one position, is structure and not content:
        # :func:`ledger_identity` namespaces a configured
        # ``api.keys[].principal`` as ``key<SEP><name>``, so banning the byte
        # here would stop every named principal from resolving. Anything else
        # -- a second separator, another namespace, an empty name -- is one
        # component pretending to be several, so what is checked is the shape.
        # With ``agent_id`` and ``peer`` separator-free and ``auth_principal``
        # either separator-free or exactly ``key<SEP><name>``, the joined
        # string parses back to one component tuple and only one, which is
        # what makes the digest a name for a caller. ``api.keys[].principal``
        # refuses control characters at config load, so the operator's end is
        # closed too.
        namespace, _, name = auth_principal.partition(_SEP)
        if namespace != "key" or not name or _SEP in name:
            _refuse("auth_principal")
    parts = [f"agent{_SEP}{agent_id}"]
    if auth_principal:
        parts.append(f"auth{_SEP}{auth_principal}")
    elif peer:
        parts.append(f"peer{_SEP}{peer}")
    digest = hashlib.sha256(_SEP.join(parts).encode("utf-8")).hexdigest()
    return f"principal:{digest[:32]}"


__all__ = ["derive_principal_id", "ledger_identity"]
