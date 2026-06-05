"""Nautilus built-in Fathom rules tree.

``BUILT_IN_RULES_DIR`` is the directory that contains the Fathom YAML
subtree (``templates/``, ``modules/``, ``functions/``, ``rules/``) that
Nautilus ships as defaults. Callers (notably ``FathomRouter`` and the
Phase 1 smoke test) resolve sibling subdirectories from it.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fathom import Engine

BUILT_IN_RULES_DIR: Path = Path(__file__).parent

# Module yamls in dependency order. fathom's ``load_modules`` globs
# ``*.yaml`` unsorted and applies each file's ``focus_order`` immediately,
# so a file whose focus references a module from another file must load
# after it: ``curator.yaml``'s focus_order names ``nautilus-routing``.
_BUILT_IN_MODULE_FILES: tuple[str, ...] = (
    "nautilus-routing.yaml",
    "curator.yaml",
)


def load_built_in_modules(engine: Engine) -> None:
    """Load the built-in module yamls into *engine* in dependency order."""
    for name in _BUILT_IN_MODULE_FILES:
        engine.load_modules(str(BUILT_IN_RULES_DIR / "modules" / name))


__all__ = ["BUILT_IN_RULES_DIR", "load_built_in_modules"]
