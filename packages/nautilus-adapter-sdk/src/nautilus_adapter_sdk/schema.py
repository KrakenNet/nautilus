"""Public SDK ``AdapterSchema`` model — re-exported from in-repo schema (#21).

Third-party adapter authors depend on this module; the in-repo
``nautilus.adapters.schema`` mirrors it.

A drift-guard test (``tests/unit/adapters/test_get_schema_drift_guard.py``)
pins this module against ``nautilus.adapters.schema`` so the two
declarations stay in sync (AC-21 risk #6).
"""

from __future__ import annotations

# Re-exports — implementation lives in the in-repo module so the canonical
# Pydantic / dataclass shape can evolve without two parallel
# implementations. SDK consumers import from this module.
from nautilus.adapters.schema import (
    AdapterField,
    AdapterSchema,
    AdapterTable,
    SchemaDiffEntry,
)

__all__ = ["AdapterField", "AdapterSchema", "AdapterTable", "SchemaDiffEntry"]
