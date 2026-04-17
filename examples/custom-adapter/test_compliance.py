"""Compliance test suite for the CSV adapter example.

Run: pytest test_compliance.py -v
"""

from __future__ import annotations

import asyncio
import csv
import tempfile
from pathlib import Path

import pytest

from nautilus_adapter_sdk.config import SourceConfig
from nautilus_adapter_sdk.testing.compliance import AdapterComplianceSuite

from csv_adapter import CsvAdapter

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_DATA = [
    {"id": "1", "name": "Alice", "department": "Engineering", "clearance": "cui-basic"},
    {"id": "2", "name": "Bob", "department": "Legal", "clearance": "cui-specified"},
    {"id": "3", "name": "Charlie", "department": "Engineering", "clearance": "unclassified"},
    {"id": "4", "name": "Dana", "department": "Security", "clearance": "cui-specified"},
]


@pytest.fixture
def csv_file(tmp_path: Path) -> Path:
    """Create a temporary CSV file with sample data."""
    path = tmp_path / "employees.csv"
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "name", "department", "clearance"])
        writer.writeheader()
        writer.writerows(SAMPLE_DATA)
    return path


@pytest.fixture
def source_config(csv_file: Path) -> SourceConfig:
    return SourceConfig(
        id="test-csv",
        type="csv",
        description="Test CSV source",
        classification="unclassified",
        data_types=["employee"],
        connection=str(csv_file),
    )


# ---------------------------------------------------------------------------
# SDK compliance suite
# ---------------------------------------------------------------------------


class TestCsvAdapterCompliance:
    """Run the official Nautilus Adapter SDK compliance tests."""

    @pytest.fixture(autouse=True)
    def _setup(self, source_config: SourceConfig) -> None:
        self.suite = AdapterComplianceSuite(
            adapter_factory=CsvAdapter,
            source_config=source_config,
        )

    @pytest.mark.asyncio
    async def test_lifecycle(self) -> None:
        await self.suite.test_connect_execute_close_lifecycle()

    @pytest.mark.asyncio
    async def test_valid_operator(self) -> None:
        await self.suite.test_scope_enforcement_valid_operator()

    @pytest.mark.asyncio
    async def test_idempotent_close(self) -> None:
        await self.suite.test_idempotent_close()


# ---------------------------------------------------------------------------
# Adapter-specific tests
# ---------------------------------------------------------------------------


class TestCsvAdapter:
    """Tests specific to CSV adapter functionality."""

    @pytest.mark.asyncio
    async def test_filter_by_department(self, source_config: SourceConfig) -> None:
        from nautilus_adapter_sdk.types import IntentAnalysis, ScopeConstraint

        adapter = CsvAdapter()
        await adapter.connect(source_config)

        result = await adapter.execute(
            IntentAnalysis(
                raw_intent="find engineers",
                normalized_intent="find_engineers",
                data_types=["employee"],
                purpose="lookup",
                confidence=1.0,
            ),
            [ScopeConstraint(
                source_id="test-csv",
                operator="=",
                field="department",
                value="Engineering",
            )],
            {},
        )

        assert len(result.data) == 2
        assert all(r["department"] == "Engineering" for r in result.data)
        await adapter.close()

    @pytest.mark.asyncio
    async def test_filter_like(self, source_config: SourceConfig) -> None:
        from nautilus_adapter_sdk.types import IntentAnalysis, ScopeConstraint

        adapter = CsvAdapter()
        await adapter.connect(source_config)

        result = await adapter.execute(
            IntentAnalysis(
                raw_intent="search",
                normalized_intent="search",
                data_types=["employee"],
                purpose="lookup",
                confidence=1.0,
            ),
            [ScopeConstraint(
                source_id="test-csv",
                operator="LIKE",
                field="name",
                value="%ali%",
            )],
            {},
        )

        assert len(result.data) == 1
        assert result.data[0]["name"] == "Alice"
        await adapter.close()

    @pytest.mark.asyncio
    async def test_no_scope_returns_all(self, source_config: SourceConfig) -> None:
        from nautilus_adapter_sdk.types import IntentAnalysis

        adapter = CsvAdapter()
        await adapter.connect(source_config)

        result = await adapter.execute(
            IntentAnalysis(
                raw_intent="list all",
                normalized_intent="list_all",
                data_types=["employee"],
                purpose="lookup",
                confidence=1.0,
            ),
            [],
            {},
        )

        assert len(result.data) == 4
        await adapter.close()
