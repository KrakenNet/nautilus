"""Nautilus core package: shared models, broker facade, and policy router.

Public exports:
- :class:`PolicyEngineError` — raised by :class:`FathomRouter` for engine
  construction or fact-assertion failures (design §3.4 failure modes).
- :class:`BrokerBusyError` — the broker is saturated; retry (503).
- :class:`Broker` — public facade (design §3.1).
- :class:`BrokerResponse` — response model (design §4.8).
"""

from __future__ import annotations


class PolicyEngineError(Exception):
    """Raised on Fathom engine construction or fact-assertion failure.

    Per design §3.4: engine construction failures surface at broker
    construction time; fact assertion / evaluation failures surface
    per-request with the offending fact payload in the message.
    """


class PurposeNotPermittedError(Exception):
    """A caller asked for a signed claim of a purpose its agent may not make.

    Distinct from a routing denial: the request never runs. Transports answer
    403 — the credential is real, the assertion it asked for is not one the
    registry supports.
    """


class SessionNotOwnedError(Exception):
    """A caller named a session id that belongs to a different principal.

    The cumulative-exposure ledger is a policy input, and a session id is a
    string the caller picks. Without an owner, any credential could pour
    exposure into any session by naming it — driving another caller's
    escalation, and reading the result back through which rules fired.

    The first principal to touch a session owns it. Another principal joins
    only where the session carries a handoff declared to its agent, which is
    the supported way a session spans agents. Transports answer 403.
    """


class BrokerBusyError(Exception):
    """Raised when the broker refuses a request rather than queue it further.

    Two places produce it, both backpressure rather than failure:

    - the exposure-ledger lock, when a caller's earlier request has held it
      past ``session_store.lock_timeout_s``. Requests from one caller are
      serialised on purpose -- two that both read the ledger empty both pass a
      cumulative cap -- but the wait used to sit outside every deadline in the
      config, so a caller measured 32 seconds to an HTTP 200;
    - the HTTP surface's ``api.max_concurrent_requests`` gate.

    The transports map it to 503 with ``Retry-After``: it is worth retrying,
    which is precisely what a 500 does not say.

    ``endpoint`` is the session store's ``scheme://host[:port]`` for the ledger
    case, and ``None`` for the in-process concurrency gate, which dials
    nothing. ``nautilus.core.broker._broker_error`` copies it onto the
    ``<broker>`` :class:`~nautilus.core.models.ErrorRecord`, so the request
    that *failed* names the dependency that failed it.
    """

    def __init__(self, message: str, *, endpoint: str | None = None) -> None:
        super().__init__(message)
        self.endpoint: str | None = endpoint


class ConsistencyError(PolicyEngineError):
    """Raised when post-run engine output fails a consistency check (#27).

    Mitigates the design §4-ops failure mode where a meta-rule or manual
    rule triggers an unexpected retraction cascade, leaving working memory
    inconsistent (e.g. session exposure facts retracted mid-evaluation).
    ``check_name`` identifies the specific assertion that fired so the
    audit trail and operators can pinpoint the offending rule class.
    """

    def __init__(self, check_name: str, message: str) -> None:
        super().__init__(f"consistency check {check_name!r} failed: {message}")
        self.check_name: str = check_name


# Re-exports for ``from nautilus.core import Broker, BrokerResponse``.
# Placed after ``PolicyEngineError`` definition because
# ``nautilus.core.broker`` imports it at module load time.
from nautilus.core.attestation_sink import (  # noqa: E402
    AttestationPayload,
    AttestationSink,
    FileAttestationSink,
    NullAttestationSink,
)
from nautilus.core.broker import Broker  # noqa: E402
from nautilus.core.models import BrokerResponse  # noqa: E402
from nautilus.core.session import (  # noqa: E402
    AsyncSessionStore,
    InMemorySessionStore,
    SessionStore,
)
from nautilus.core.session_pg import (  # noqa: E402
    PostgresSessionStore,
    SessionStoreUnavailableError,
)
from nautilus.core.session_sqlite import SqliteSessionStore  # noqa: E402

__all__ = [
    "AsyncSessionStore",
    "AttestationPayload",
    "AttestationSink",
    "Broker",
    "BrokerBusyError",
    "PurposeNotPermittedError",
    "SessionNotOwnedError",
    "BrokerResponse",
    "ConsistencyError",
    "FileAttestationSink",
    "InMemorySessionStore",
    "NullAttestationSink",
    "PolicyEngineError",
    "PostgresSessionStore",
    "SessionStore",
    "SessionStoreUnavailableError",
    "SqliteSessionStore",
]
