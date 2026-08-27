"""Compliance suite third-party adapters run against their own implementation.

``nautilus adapters new`` scaffolds a package whose tests import this suite.
It used to live only in ``nautilus-adapter-sdk``, which is not published, so
the generated package could not be installed outside this repository — see
``docs/reference/adapter-sdk.md``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from nautilus.adapters.base import Adapter, AdapterError, ScopeEnforcementError
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint


class AdapterComplianceSuite:
    """Compliance test harness for adapter implementations.

    Parameterised via *adapter_factory* (a callable returning an Adapter
    instance) and *source_config* (the SourceConfig to connect with).

    Usage::

        suite = AdapterComplianceSuite(
            adapter_factory=lambda: MyAdapter(),
            source_config=SourceConfig(
                id="s1", type="mytype", classification="unclassified", data_types=["generic"]
            ),
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
            data_types_needed=["generic"],
            entities=[],
        )

    def _make_context(self) -> dict[str, Any]:
        """The third argument as the broker builds it.

        The suite used to pass ``{}``, so an adapter that reads its stated
        purpose or session id -- as every shipped adapter does -- was never
        exercised on the path it actually runs on.
        """
        return {"purpose": "testing", "session_id": "compliance", "clearance": "unclassified"}

    def _make_scope(self, operator: str = "=") -> list[ScopeConstraint]:
        # ``model_construct`` rather than the constructor: ``operator`` is a
        # Literal on the broker's own model, so the unsupported-operator check
        # below could not build its own input otherwise. An adapter still has
        # to refuse what reaches it -- validation upstream is not a substitute
        # for failing closed.
        return [
            ScopeConstraint.model_construct(
                source_id=self.source_config.id,
                operator=operator,  # pyright: ignore[reportArgumentType]
                field="id",
                value="test",
            )
        ]

    # -- test methods ---------------------------------------------------

    async def test_connect_execute_close_lifecycle(self) -> None:
        """Test full adapter lifecycle: connect -> execute -> close."""
        adapter: Adapter = self.adapter_factory()
        await adapter.connect(self.source_config)
        result = await adapter.execute(  # sqlgrep: ignore - adapter call, not SQL
            self._make_intent(), self._make_scope(), self._make_context()
        )
        assert isinstance(result, AdapterResult), (
            f"execute must return an AdapterResult, got {type(result).__name__}"
        )
        await adapter.close()

    async def test_scope_enforcement_valid_operator(self) -> None:
        """Validate that a valid scope operator is accepted."""
        adapter: Adapter = self.adapter_factory()
        await adapter.connect(self.source_config)
        try:
            result = await adapter.execute(  # sqlgrep: ignore - adapter call, not SQL
                self._make_intent(), self._make_scope("="), self._make_context()
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
                await adapter.execute(  # sqlgrep: ignore - adapter call, not SQL
                    self._make_intent(),
                    self._make_scope("INVALID_OP"),
                    self._make_context(),
                )
            except ScopeEnforcementError:
                raised = True
            assert raised, "an unsupported scope operator must raise ScopeEnforcementError"
        finally:
            await adapter.close()

    async def test_idempotent_close(self) -> None:
        """Calling close() twice must not raise."""
        adapter: Adapter = self.adapter_factory()
        await adapter.connect(self.source_config)
        await adapter.close()
        await adapter.close()  # second call must not error

    async def test_error_path_reports_the_failure(self) -> None:
        """A failing query must report, not return junk.

        Two shapes are compliant, because both are what the broker handles:
        an :class:`AdapterResult` whose ``error`` is populated, or a raised
        :class:`AdapterError`, which ``Broker._execute_adapter`` catches and
        turns into exactly that. Every shipped adapter takes the second path,
        which the previous version of this check failed outright.
        """
        adapter: Adapter = self.adapter_factory()
        await adapter.connect(self.source_config)
        try:
            # Use an impossible intent to trigger error path
            bad_intent = IntentAnalysis(
                raw_intent="__compliance_error_trigger__",
                data_types_needed=["nonexistent"],
                entities=[],
            )
            try:
                result = await adapter.execute(  # sqlgrep: ignore - adapter call, not SQL
                    bad_intent, self._make_scope(), self._make_context()
                )
            except AdapterError:
                return
            assert isinstance(result, AdapterResult), (
                f"the error path must return an AdapterResult carrying an "
                f"ErrorRecord, or raise AdapterError; got {type(result).__name__}"
            )
        finally:
            await adapter.close()


__all__ = ["AdapterComplianceSuite"]
