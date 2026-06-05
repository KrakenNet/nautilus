"""Nautilus-owned session-attestation package (#18).

Hosts ``SessionTokenService``, ``KeyRing``, and the JWKS exporter that
back ACs AC-18.a through AC-18.g. Disjoint from Fathom's response-only
``AttestationService`` (PRD Risk #5): Fathom's signer is single-key and
cannot satisfy AC-18.e's ≥2-active-key rotation window.

Module-layout source of truth: ``.forge/shared.md`` "Module layout".
"""

from __future__ import annotations
