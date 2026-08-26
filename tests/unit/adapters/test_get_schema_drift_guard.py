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


def test_sdk_schema_dataclasses_mirror_the_in_repo_ones() -> None:
    """The vendored SDK schema types must match the in-repo definitions.

    The SDK vendors these rather than importing them, so that a package that
    installed only ``nautilus-adapter-sdk`` does not need asyncpg,
    elasticsearch, neo4j, fastapi and the rest of the core distribution for
    four dataclasses. Vendoring is only safe with this guard.
    """
    import dataclasses

    from nautilus_adapter_sdk import schema as sdk_schema

    from nautilus.adapters import schema as core_schema

    for name in ("AdapterField", "AdapterTable", "AdapterSchema", "SchemaDiffEntry"):
        sdk_fields = {f.name: str(f.type) for f in dataclasses.fields(getattr(sdk_schema, name))}
        core_fields = {f.name: str(f.type) for f in dataclasses.fields(getattr(core_schema, name))}
        assert sdk_fields == core_fields, f"{name} has drifted: sdk={sdk_fields} core={core_fields}"


def test_sdk_and_core_fingerprints_agree() -> None:
    """A schema fingerprinted by an SDK adapter must equal the broker's.

    The fingerprint is the drift baseline. Two algorithms that disagree make
    every SDK-built adapter look permanently drifted.
    """
    from datetime import UTC, datetime

    from nautilus_adapter_sdk import schema as sdk_schema

    from nautilus.adapters import schema as core_schema

    def build(mod: object) -> object:
        field = mod.AdapterField(name="c", type="text", nullable=False)  # type: ignore[attr-defined]
        table = mod.AdapterTable(  # type: ignore[attr-defined]
            name="t", fields=(field,), indexes=("i",), primary_key=("c",)
        )
        return mod.AdapterSchema(  # type: ignore[attr-defined]
            adapter_id="a",
            source_type="postgres",
            tables=(table,),
            capability_flags={"scope": True},
            fetched_at=datetime.now(UTC),
        )

    assert build(sdk_schema).fingerprint() == build(core_schema).fingerprint()  # type: ignore[attr-defined]
