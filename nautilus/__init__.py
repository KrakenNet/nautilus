"""Nautilus — Intelligent Data Broker for AI Agents (Phase 1).

Top-level re-exports for the public SDK surface.
"""

from __future__ import annotations

from nautilus.core.broker import Broker
from nautilus.core.models import BrokerResponse

__version__ = "0.2.2"  # x-release-please-version

__all__ = ["Broker", "BrokerResponse", "__version__"]
