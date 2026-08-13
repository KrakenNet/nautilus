"""Nautilus rule packs, discoverable through fathom's ``fathom.packs`` entry points.

Each subpackage is a pack directory in the layout ``fathom.packs.RulePackLoader``
expects — ``templates/``, ``modules/``, ``functions/``, ``rules/`` — so
``Engine.load_pack("data-routing-nist")`` resolves the entry point declared in
``pyproject.toml``, takes the subpackage's ``__path__``, and loads each
subdirectory in dependency order.

Packs live inside the Python package rather than at the repository root so they
ship in the installed wheel; see ``[tool.setuptools.package-data]``.
"""

from __future__ import annotations

__all__: list[str] = []
