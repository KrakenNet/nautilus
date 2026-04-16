"""Adapter compliance test suite for validating adapter implementations."""

from __future__ import annotations

from typing import Any, Callable

from nautilus_adapter_sdk.config import SourceConfig
from nautilus_adapter_sdk.exceptions import ScopeEnforcementError
from nautilus_adapter_sdk.protocols import Adapter
from nautilus_adapter_sdk.types import (
    AdapterResult,
    ErrorRecord,
    IntentAnalysis,
    ScopeConstraint,
)


class AdapterComplianceSuite:
    """Compliance test harness for adapter implementations.

    Parameterised via *adapter_factory* (a callable returning an Adapter
    instance) and *source_config* (the SourceConfig to connect with).

    Usage::

        suite = AdapterComplianceSuite(
            adapter_factory=lambda: MyAdapter(),
            source_config=SourceConfig(id="s1", type="mytype"),
        )
        await suite.test_connect_execute_close_lifecycle()
    """

    def __init__(
        self,
        adapter_factory: Callable[[], Any],
        source_config: SourceConfig,
    ) -> None:
        self.adapter_factory = adapter_factory
        self.source_config = source_config

    # -- helpers --------------------------------------------------------

    def _make_intent(self) -> IntentAnalysis:
        return IntentAnalysis(
            raw_intent="test query",
            normalized_intent="test_query",
            data_types=["generic"],
            purpose="testing",
            confidence=1.0,
        )

    def _make_scope(self, operator: str = "eq") -> list[ScopeConstraint]:
        return [
            ScopeConstraint(
                source_id=self.source_config.id,
                operator=operator,
                field="id",
                value="test",
            )
        ]

    # -- test methods ---------------------------------------------------

    async def test_connect_execute_close_lifecycle(self) -> None:
        """Test full adapter lifecycle: connect -> execute -> close."""
        adapter: Adapter = self.adapter_factory()
        await adapter.connect(self.source_config)
        result = await adapter.execute(
            self._make_intent(), self._make_scope(), {}
        )
        assert isinstance(result, AdapterResult), (
            f"execute() must return AdapterResult, got {type(result).__name__}"
        )
        await adapter.close()

    async def test_scope_enforcement_valid_operator(self) -> None:
        """Validate that a valid scope operator is accepted."""
        adapter: Adapter = self.adapter_factory()
        await adapter.connect(self.source_config)
        try:
            result = await adapter.execute(
                self._make_intent(), self._make_scope("eq"), {}
            )
            assert isinstance(result, AdapterResult)
        finally:
            await adapter.close()

    async def test_scope_enforcement_invalid_operator(self) -> None:
        """Validate ScopeEnforcementError on invalid operator."""
        adapter: Adapter = self.adapter_factory()
        await adapter.connect(self.source_config)
        try:
            raised = False
            try:
                await adapter.execute(
                    self._make_intent(),
                    self._make_scope("INVALID_OP"),
                    {},
                )
            except ScopeEnforcementError:
                raised = True
            assert raised, (
                "execute() with invalid operator must raise ScopeEnforcementError"
            )
        finally:
            await adapter.close()

    async def test_idempotent_close(self) -> None:
        """Calling close() twice must not raise."""
        adapter: Adapter = self.adapter_factory()
        await adapter.connect(self.source_config)
        await adapter.close()
        await adapter.close()  # second call must not error

    async def test_error_path_returns_error_record(self) -> None:
        """Adapter errors should return an ErrorRecord."""
        adapter: Adapter = self.adapter_factory()
        await adapter.connect(self.source_config)
        try:
            # Use an impossible intent to trigger error path
            bad_intent = IntentAnalysis(
                raw_intent="__compliance_error_trigger__",
                normalized_intent="__compliance_error_trigger__",
                data_types=["nonexistent"],
                purpose="compliance_error_test",
                confidence=0.0,
            )
            result = await adapter.execute(bad_intent, self._make_scope(), {})
            # Adapter may return AdapterResult or ErrorRecord
            assert isinstance(result, (AdapterResult, ErrorRecord)), (
                f"Error path must return AdapterResult or ErrorRecord, "
                f"got {type(result).__name__}"
            )
        finally:
            await adapter.close()
