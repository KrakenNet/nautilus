"""Nautilus core package: shared models, broker facade, and policy router.

Public exports:
- :class:`PolicyEngineError` — raised by :class:`FathomRouter` for engine
  construction or fact-assertion failures (design §3.4 failure modes).
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

__all__ = [
    "AsyncSessionStore",
    "AttestationPayload",
    "AttestationSink",
    "Broker",
    "BrokerResponse",
    "FileAttestationSink",
    "InMemorySessionStore",
    "NullAttestationSink",
    "PolicyEngineError",
    "PostgresSessionStore",
    "SessionStore",
    "SessionStoreUnavailableError",
]
