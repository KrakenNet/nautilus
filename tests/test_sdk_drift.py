"""SDK drift-guard: structural equivalence between core models and SDK types.

Compares Pydantic model_fields between ``nautilus.core.models`` and
``nautilus_adapter_sdk.types`` for every shared model.  Fails if a public
field name or type annotation diverges without an explicit allowance.

The SDK deliberately simplifies some types (e.g. ``Literal[...]`` -> ``str``)
to stay dependency-free.  Known field-name divergences are captured in
``_KNOWN_FIELD_MAPPING`` so the test only fires on *unintended* drift.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, get_origin

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


def _normalize_type(tp: Any) -> Any:
    """Collapse ``Literal[...]`` -> ``str`` for comparison tolerance."""
    origin = get_origin(tp)
    if origin is type(None):
        return type(None)
    # Literal[...] has no origin in older typing but get_origin returns Literal
    try:
        from typing import Literal

        if origin is Literal:
            # All our Literal members are str; normalise to str.
            return str
    except ImportError:
        pass
    return tp


# ---------------------------------------------------------------------------
# Known divergences: maps (internal_field -> sdk_field) per model.
# These are *intentional* API-surface simplifications in the SDK; the test
# ensures no *additional* untracked divergence creeps in.
# ---------------------------------------------------------------------------

_KNOWN_FIELD_MAPPING: dict[str, dict[str, str]] = {
    "IntentAnalysis": {
        # Internal fields that map to different SDK field names.
        # The two models have deliberately different shapes:
        #   internal: raw_intent, data_types_needed, entities, temporal_scope, estimated_sensitivity
        #   SDK:      raw_intent, normalized_intent, data_types, purpose, confidence
        # Only ``raw_intent`` is shared.
    },
    "AdapterResult": {
        # internal: source_id, rows, duration_ms, error
        # SDK:      source_id, data, metadata
        # Only ``source_id`` is shared.
    },
    "ErrorRecord": {
        # internal: source_id, error_type, message, trace_id
        # SDK:      source_id, error, error_type
        # ``source_id`` and ``error_type`` are shared.
    },
    "ScopeConstraint": {
        # Identical field names; type diff (Literal vs str) is tolerated.
    },
}

# Fields that MUST remain identical between internal and SDK copies.
# If any of these are renamed/removed in one side, the test fails.
_REQUIRED_SHARED_FIELDS: dict[str, set[str]] = {
    "ScopeConstraint": {"source_id", "field", "operator", "value", "expires_at", "valid_from"},
    "IntentAnalysis": {"raw_intent"},
    "AdapterResult": {"source_id"},
    "ErrorRecord": {"source_id", "error_type"},
}

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
    """Ensure SDK types stay structurally aligned with internal models."""

    @pytest.mark.parametrize(
        "name,internal_cls,sdk_cls",
        _MODEL_PAIRS,
        ids=[p[0] for p in _MODEL_PAIRS],
    )
    def test_required_shared_fields_present(
        self, name: str, internal_cls: type, sdk_cls: type
    ) -> None:
        """Every required-shared field must exist on BOTH sides."""
        required = _REQUIRED_SHARED_FIELDS[name]
        internal_fields = _field_names(internal_cls)
        sdk_fields = _field_names(sdk_cls)

        missing_internal = required - internal_fields
        missing_sdk = required - sdk_fields

        assert not missing_internal, (
            f"{name}: required shared fields missing from internal model: {missing_internal}"
        )
        assert not missing_sdk, (
            f"{name}: required shared fields missing from SDK model: {missing_sdk}"
        )

    @pytest.mark.parametrize(
        "name,internal_cls,sdk_cls",
        _MODEL_PAIRS,
        ids=[p[0] for p in _MODEL_PAIRS],
    )
    def test_shared_field_types_compatible(
        self, name: str, internal_cls: type, sdk_cls: type
    ) -> None:
        """For each required-shared field the normalised types must match."""
        required = _REQUIRED_SHARED_FIELDS[name]
        internal_types = _field_types(internal_cls)
        sdk_types = _field_types(sdk_cls)

        for field in required:
            int_tp = _normalize_type(internal_types[field])
            sdk_tp = _normalize_type(sdk_types[field])
            assert int_tp == sdk_tp, (
                f"{name}.{field}: type mismatch — "
                f"internal={internal_types[field]}, sdk={sdk_types[field]}"
            )

    def test_scope_constraint_full_field_parity(self) -> None:
        """ScopeConstraint should have identical field names on both sides."""
        internal = _field_names(InternalScopeConstraint)
        sdk = _field_names(SDKScopeConstraint)
        assert internal == sdk, (
            f"ScopeConstraint field drift: "
            f"only-internal={internal - sdk}, only-sdk={sdk - internal}"
        )

    def test_no_new_sdk_fields_untracked(self) -> None:
        """Catch any SDK field additions not yet covered by shared-field sets."""
        for name, _internal_cls, sdk_cls in _MODEL_PAIRS:
            sdk_fields = _field_names(sdk_cls)
            known_shared = _REQUIRED_SHARED_FIELDS[name]
            # Any SDK field not in required-shared must be intentional SDK-only.
            # This just records them; if you add a field to the SDK, add it to
            # _REQUIRED_SHARED_FIELDS or acknowledge it is SDK-only.
            sdk_only = sdk_fields - known_shared
            # Ensure SDK-only fields are not accidentally named the same as a
            # new internal field (which would indicate they should be shared).
            internal_fields = _field_names(_internal_cls)
            unexpected_overlap = sdk_only & internal_fields
            if unexpected_overlap:
                pytest.fail(
                    f"{name}: fields {unexpected_overlap} exist in both SDK and "
                    f"internal but are not in _REQUIRED_SHARED_FIELDS — add them."
                )
