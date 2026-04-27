"""Nautobot-specific error classes (Task 46, AC-1.11)."""

from __future__ import annotations

from nautilus.adapters.base import AdapterError


class NautobotAuthError(AdapterError):
    """HTTP 403 / 401 from Nautobot — token rejected or insufficient scope.

    Carries an optional ``kind`` discriminator that callers may inspect to
    distinguish ``"forbidden"`` (token valid but lacks permission) from
    ``"missing_token"`` (no Authorization header recognised).
    """

    def __init__(self, message: str, *, kind: str = "forbidden") -> None:
        super().__init__(message)
        self.kind = kind


class NautobotUnsupportedOperation(AdapterError):  # noqa: N818 - public API name, "Operation" is the intended noun
    """Raised for v1-rejected writes (device creation, IP assignment, etc.).

    GraphQL is read-only in Nautobot 3.1 and the REST write path is
    explicitly out of scope per AC-1.6 / Out-of-Scope item 7.
    """


class NautobotGraphQLPartialError(AdapterError):
    """``{data, errors}`` envelope with non-empty ``errors`` and ``data is None``.

    When ``data`` is also populated the adapter returns the partial result
    plus an audit warning; when ``data`` is ``None`` this exception is raised.
    """


class NautobotExecutionError(AdapterError):
    """Catch-all for unexpected non-auth runtime failures."""
