"""Drift-guard: in-repo Adapter Protocol vs SDK Adapter Protocol (AC-21 risk #6).

Pairs ``nautilus.adapters.base.Adapter`` with the SDK
``nautilus_adapter_sdk.protocols.Adapter`` so the two declarations stay
in sync. Mirrors :mod:`tests.unit.test_operator_allowlist_drift`.
"""

from __future__ import annotations

import inspect

import pytest

pytestmark = pytest.mark.unit


def test_ac_21_a_in_repo_protocol_has_get_schema() -> None:
    from nautilus.adapters.base import Adapter as InRepoAdapter

    assert "get_schema" in dir(InRepoAdapter), (
        "AC-21.a: nautilus/adapters/base.py:128 Adapter Protocol must add "
        "async def get_schema(self) -> AdapterSchema"
    )


def test_ac_21_a_sdk_protocol_has_get_schema() -> None:
    from nautilus_adapter_sdk.protocols import Adapter as SdkAdapter

    assert "get_schema" in dir(SdkAdapter), (
        "AC-21.a: packages/nautilus-adapter-sdk/.../protocols.py:13 "
        "Adapter Protocol must add async def get_schema(self) -> AdapterSchema "
        "in lockstep with the in-repo Protocol"
    )


def test_ac_21_a_get_schema_signatures_match() -> None:
    from nautilus_adapter_sdk.protocols import Adapter as SdkAdapter

    from nautilus.adapters.base import Adapter as InRepoAdapter

    in_repo = inspect.signature(InRepoAdapter.get_schema)
    sdk = inspect.signature(SdkAdapter.get_schema)
    assert str(in_repo) == str(sdk), f"AC-21.a Protocol drift: in-repo {in_repo} vs SDK {sdk}"
