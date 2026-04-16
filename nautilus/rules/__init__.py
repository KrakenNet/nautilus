"""Nautilus built-in Fathom rules tree.

``BUILT_IN_RULES_DIR`` is the directory that contains the Fathom YAML
subtree (``templates/``, ``modules/``, ``functions/``, ``rules/``) that
Nautilus ships as defaults. Callers (notably ``FathomRouter`` and the
Phase 1 smoke test) resolve sibling subdirectories from it.
"""

from __future__ import annotations

from pathlib import Path

BUILT_IN_RULES_DIR: Path = Path(__file__).parent

__all__ = ["BUILT_IN_RULES_DIR"]
