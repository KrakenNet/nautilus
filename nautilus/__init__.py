"""Nautilus — Intelligent Data Broker for AI Agents (Phase 1).

Top-level re-exports for the public SDK surface.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

from nautilus.core.broker import Broker
from nautilus.core.models import BrokerResponse

# One source of truth for the version: ``[project] version`` in pyproject.toml,
# which the build backend copies into the installed distribution's metadata.
# Reading it back means the string this process reports is the one the wheel it
# was installed from was built with. A literal here is a second source that can
# disagree with the first -- it did in 0.1.4, which shipped needing a "sync
# nautilus/__init__.py __version__" follow-up. ``nautilus version`` (the CLI)
# has always read distribution metadata; this makes the library agree with it.
try:
    __version__ = _distribution_version("nautilus-rkm")
except PackageNotFoundError:  # pragma: no cover - source tree that was never installed
    # Honest, and unmistakably not a release: the source tree cannot know which
    # build it would become.
    __version__ = "0+unknown"

__all__ = ["Broker", "BrokerResponse", "__version__"]
