"""Meta-test: enforce one dedicated unit-test module per core component (Task 3.19).

AC-9.5 requires that each first-class component of the broker have its own
dedicated ``tests/unit/test_<component>.py`` module. Coverage ratchets (Task
3.18) keep line/branch coverage honest, but they do not prevent someone from
collapsing all of a component's tests into another file and losing the
per-component seam that makes regressions localisable.

This module guards that structural invariant: if any of the expected
per-component unit-test files is deleted or renamed, this test fails and
surfaces the missing file(s) by name, so the offending change cannot land
silently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Expected per-component unit-test modules (AC-9.5).
#
# Each entry is a path RELATIVE to ``tests/unit/`` using forward-slash
# separators. Phase-1 (core-broker) entries live directly under
# ``tests/unit/``; Phase-3 (reasoning-engine, Task 3.18) entries live in
# per-package subdirectories mirroring ``nautilus/`` so each component keeps
# its own dedicated seam.
_EXPECTED_MODULES: tuple[str, ...] = (
    # --- Phase 1 (core-broker, tasks 3.1–3.11) -----------------------------
    "test_config_loader.py",
    "test_source_registry.py",
    "test_pattern_analyzer.py",
    "test_fathom_router.py",
    "test_postgres_adapter.py",
    "test_pgvector_adapter.py",
    "test_synthesizer.py",
    "test_audit_logger.py",
    "test_broker.py",
    # --- Phase 3 (reasoning-engine, Task 3.18) -----------------------------
    # Session + temporal + scope-hash + attestation + declare-handoff
    "core/test_session_pg_unit.py",
    "core/test_temporal.py",
    "core/test_scope_hash_v2.py",
    "core/test_attestation_sink.py",
    "core/test_declare_handoff.py",
    # Adapters
    "adapters/test_elasticsearch.py",
    "adapters/test_rest.py",
    "adapters/test_neo4j.py",
    "adapters/test_servicenow.py",
    # Analysis fallback + transport auth
    "analysis/test_fallback.py",
    "transport/test_auth.py",
    # Transport entrypoints + CLI
    "transport/test_fastapi_unit.py",
    "transport/test_mcp_unit.py",
    "test_cli.py",
    # Forensics
    "forensics/test_handoff_worker.py",
    "forensics/test_offsets.py",
    "forensics/test_sinks.py",
    # Rules
    "rules/test_contains_all_external.py",
    "rules/test_classification_rule.py",
    "rules/test_information_flow_rule.py",
)

_UNIT_DIR: Path = Path(__file__).parent


def _module_path(module_name: str) -> Path:
    """Resolve a ``tests/unit/``-relative module name to an absolute path."""
    return _UNIT_DIR.joinpath(*module_name.split("/"))


@pytest.mark.unit
@pytest.mark.parametrize("module_name", _EXPECTED_MODULES)
def test_dedicated_unit_module_exists(module_name: str) -> None:
    """Each expected per-component unit-test module MUST exist."""
    module_path = _module_path(module_name)
    assert module_path.is_file(), (
        f"Missing dedicated unit-test module '{module_name}' in {_UNIT_DIR}. "
        "AC-9.5 requires one dedicated tests/unit/test_<component>.py per "
        "first-class component."
    )


@pytest.mark.unit
def test_all_expected_modules_present() -> None:
    """Aggregate guard: report every missing module in a single failure."""
    missing = [name for name in _EXPECTED_MODULES if not _module_path(name).is_file()]
    assert not missing, (
        "Missing dedicated unit-test modules (AC-9.5): "
        f"{sorted(missing)}. Expected each of {sorted(_EXPECTED_MODULES)} to "
        f"exist in {_UNIT_DIR}."
    )
