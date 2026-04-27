"""Nautobot 3.1 adapter for the Nautilus broker.

GraphQL is the primary transport (POST ``/api/graphql/`` with
``Authorization: Token <token>``); REST fallback at ``/api/...`` covers
five Nautobot features GraphQL cannot express in v3.1: writes (rejected
in v1 with :class:`NautobotUnsupportedOperation`), total-count pagination
metadata, ``?include=config_context``, IP-to-interface M2M retrieval, and
device-cluster assignments.

Per AC-1.4 every REST call sends ``Accept: application/json; version=3.1``;
GraphQL POSTs send ``Content-Type: application/json``.
"""

from .adapter import NautobotAdapter
from .errors import (
    NautobotAuthError,
    NautobotExecutionError,
    NautobotGraphQLPartialError,
    NautobotUnsupportedOperation,
)

__version__ = "0.1.0"

__all__ = [
    "NautobotAdapter",
    "NautobotAuthError",
    "NautobotExecutionError",
    "NautobotGraphQLPartialError",
    "NautobotUnsupportedOperation",
]
