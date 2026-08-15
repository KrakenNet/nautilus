"""A test run must not append to the repository's own audit log.

``tests/fixtures/nautilus.yaml`` is shared by ~20 tests and ``audit.path``
resolves against the CWD, so every run wrote its decisions into the live,
gitignored ``audit.jsonl`` at the repo root -- 82 lines in a single pass.
That file is what a replay gate judges against, and a corpus that grows
underneath the gate cannot be reproduced.

These guard the isolation rather than the symptom: the fixture must not carry
a repo-relative path, and the harness must point somewhere outside the tree.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "nautilus.yaml"


def test_the_shared_fixture_config_does_not_hardcode_a_relative_audit_path() -> None:
    raw = FIXTURE_PATH.read_text(encoding="utf-8")
    assert "${NAUTILUS_AUDIT_PATH}" in raw, (
        "tests/fixtures/nautilus.yaml must take its audit path from the harness"
    )
    assert "path: ./audit.jsonl" not in raw


def test_the_harness_points_the_audit_log_outside_the_source_tree() -> None:
    configured = os.environ.get("NAUTILUS_AUDIT_PATH")
    assert configured is not None, "isolate_audit_log (tests/conftest.py) must set this"
    resolved = Path(configured).resolve()
    assert REPO_ROOT not in resolved.parents, f"audit log would land in the source tree: {resolved}"


def test_the_loaded_config_resolves_to_the_harness_path(
    isolate_audit_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wiring, not just the env var: the path the loader yields is the tmp one."""
    from nautilus.config.loader import load_config

    # Dummy DSNs so the fixture's own ``${TEST_*_DSN}`` interpolation resolves.
    monkeypatch.setenv("TEST_PG_DSN", "postgresql://u:p@127.0.0.1:5432/db")
    monkeypatch.setenv("TEST_PGV_DSN", "postgresql://u:p@127.0.0.1:5432/db")
    assert Path(load_config(FIXTURE_PATH).audit.path) == isolate_audit_log
