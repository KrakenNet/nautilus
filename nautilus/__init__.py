"""Nautilus — Intelligent Data Broker for AI Agents (Phase 1).

Top-level re-exports for the public SDK surface.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from nautilus.core.broker import Broker
from nautilus.core.models import BrokerResponse

try:
    __version__ = _pkg_version("nautilus-rkm")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["Broker", "BrokerResponse"]
