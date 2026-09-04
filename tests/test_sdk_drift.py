"""SDK drift-guard: structural equivalence between core models and SDK types.

Compares Pydantic model_fields between ``nautilus.core.models`` and
``nautilus_adapter_sdk.types`` for every shared model.  The SDK mirrors core
field-for-field: an adapter built against the SDK hands its result straight to
the broker, so a rename on either side breaks every out-of-tree adapter.  Two
type differences are tolerated because the SDK stays dependency-free and
carries its own copies: ``Literal[...]`` relaxes to ``str``, and a nested model
resolves to the SDK's same-named class.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Literal, get_origin

import pytest

# ---------------------------------------------------------------------------
# SDK uses src-layout in packages/; ensure importable without pip install.
# ---------------------------------------------------------------------------
_SDK_SRC = str(Path(__file__).resolve().parent.parent / "packages" / "nautilus-adapter-sdk" / "src")
if _SDK_SRC not in sys.path:
    sys.path.insert(0, _SDK_SRC)

from nautilus_adapter_sdk.types import AdapterResult as SDKAdapterResult  # noqa: E402
from nautilus_adapter_sdk.types import ErrorRecord as SDKErrorRecord  # noqa: E402
from nautilus_adapter_sdk.types import IntentAnalysis as SDKIntentAnalysis  # noqa: E402
from nautilus_adapter_sdk.types import ScopeConstraint as SDKScopeConstraint  # noqa: E402

from nautilus.core.models import AdapterResult as InternalAdapterResult  # noqa: E402
from nautilus.core.models import ErrorRecord as InternalErrorRecord  # noqa: E402
from nautilus.core.models import IntentAnalysis as InternalIntentAnalysis  # noqa: E402
from nautilus.core.models import ScopeConstraint as InternalScopeConstraint  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _field_names(model_cls: Any) -> set[str]:
    """Return public field names from a Pydantic v2 model."""
    return set(model_cls.model_fields.keys())  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]


def _field_types(model_cls: Any) -> dict[str, Any]:
    """Return ``{field_name: annotation}`` for a Pydantic v2 model."""
    return {  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType]
        name: info.annotation for name, info in model_cls.model_fields.items()
    }


def _type_key(tp: Any) -> str:
    """Comparable spelling of an annotation, tolerant of the two known diffs."""
    if get_origin(tp) is Literal:
        # Every Literal member in these models is a str; the SDK ships the
        # relaxed type so adapter authors need no enum import.
        return "str"
    text = str(tp)
    for prefix in ("nautilus_adapter_sdk.types.", "nautilus.core.models."):
        text = text.replace(prefix, "")
    return text.replace("<class '", "").replace("'>", "")


_MODEL_PAIRS: list[tuple[str, type, type]] = [
    ("ScopeConstraint", InternalScopeConstraint, SDKScopeConstraint),
    ("IntentAnalysis", InternalIntentAnalysis, SDKIntentAnalysis),
    ("AdapterResult", InternalAdapterResult, SDKAdapterResult),
    ("ErrorRecord", InternalErrorRecord, SDKErrorRecord),
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSDKDriftGuard:
    """Ensure SDK types stay structurally identical to internal models."""

    @pytest.mark.parametrize(
        "name,internal_cls,sdk_cls",
        _MODEL_PAIRS,
        ids=[p[0] for p in _MODEL_PAIRS],
    )
    def test_field_names_match(self, name: str, internal_cls: type, sdk_cls: type) -> None:
        internal = _field_names(internal_cls)
        sdk = _field_names(sdk_cls)
        assert internal == sdk, (
            f"{name} field drift: only-internal={internal - sdk}, only-sdk={sdk - internal}"
        )

    @pytest.mark.parametrize(
        "name,internal_cls,sdk_cls",
        _MODEL_PAIRS,
        ids=[p[0] for p in _MODEL_PAIRS],
    )
    def test_field_types_match(self, name: str, internal_cls: type, sdk_cls: type) -> None:
        internal_types = _field_types(internal_cls)
        sdk_types = _field_types(sdk_cls)
        for field in sorted(set(internal_types) & set(sdk_types)):
            assert _type_key(internal_types[field]) == _type_key(sdk_types[field]), (
                f"{name}.{field}: type mismatch — "
                f"internal={internal_types[field]}, sdk={sdk_types[field]}"
            )

    def test_the_guard_can_actually_see_a_rename(self) -> None:
        """Control: the comparison fails when a field really does diverge."""

        class Renamed(SDKErrorRecord):
            other_name: str = ""

        assert _field_names(Renamed) != _field_names(InternalErrorRecord)
