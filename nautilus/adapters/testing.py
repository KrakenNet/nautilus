"""Compliance suite third-party adapters run against their own implementation.

``nautilus adapters new`` scaffolds a package whose tests import this suite.
It used to live only in ``nautilus-adapter-sdk``, which is not published, so
the generated package could not be installed outside this repository — see
``docs/reference/adapter-sdk.md``.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable
from typing import Any

from nautilus.adapters.base import Adapter, AdapterError, ScopeEnforcementError
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# A value no real fixture holds, so any row returned beside it contradicts the
# constraint the adapter accepted.
_NO_SUCH_VALUE = "nautilus-compliance-no-such-id-8f4c1e0a"


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

    def _make_scope(self, operator: str = "=", value: str = "test") -> list[ScopeConstraint]:
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
                value=value,
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
        """A supported operator has to narrow the rows, not merely be tolerated.

        This asserted only ``isinstance(result, AdapterResult)``, so it passed an
        adapter that took the constraint, ignored it, and returned every row --
        the one failure the scope contract exists to prevent. The broker does not
        re-check returned rows against the constraint it issued, so this suite is
        the gate; certifying an adapter that enforces nothing put a false receipt
        in the signed attestation, which recorded the constraint as applied.

        Two runs, one connection:

        * ``id = "test"`` -- the matching probe, and the row budget for the check.
        * ``id = <a value nothing holds>`` -- the refuting probe.

        A row that comes back from the refuting probe carrying a different ``id``
        is a contradiction of the predicate the adapter accepted, and fails. An
        adapter that projects ``id`` away is caught by the second assertion: it
        cannot return the same rows for both probes.

        A source that returns nothing for the matching probe cannot discriminate,
        so the checks below are vacuous. That is warned about rather than failed:
        a freshly scaffolded adapter points at a backend the suite cannot seed,
        and a compliance run that fails on an empty fixture teaches the author to
        delete the test. The warning names what to do instead.
        """
        adapter: Adapter = self.adapter_factory()
        await adapter.connect(self.source_config)
        try:
            matching = await adapter.execute(  # sqlgrep: ignore - adapter call, not SQL
                self._make_intent(), self._make_scope("="), self._make_context()
            )
            assert isinstance(matching, AdapterResult), (
                f"execute must return an AdapterResult, got {type(matching).__name__}"
            )
            refuting = await adapter.execute(  # sqlgrep: ignore - adapter call, not SQL
                self._make_intent(),
                self._make_scope("=", value=_NO_SUCH_VALUE),
                self._make_context(),
            )
            assert isinstance(refuting, AdapterResult), (
                f"execute must return an AdapterResult, got {type(refuting).__name__}"
            )

            contradicting = [
                row
                for row in refuting.rows
                if "id" in row and str(row["id"]) != _NO_SUCH_VALUE
            ]
            assert not contradicting, (
                f"the adapter returned {len(contradicting)} row(s) that contradict the "
                f"scope constraint it accepted (id = {_NO_SUCH_VALUE!r}); first offender: "
                f"{contradicting[0]!r}. Apply the constraint, or raise "
                f"ScopeEnforcementError for the operators you cannot enforce -- "
                f"returning unscoped rows makes the signed attestation a false receipt."
            )

            if not matching.rows:
                warnings.warn(
                    "AdapterComplianceSuite could not verify scope enforcement: the "
                    "source returned no rows for id = 'test', so an adapter that "
                    "ignores the constraint is indistinguishable from one that "
                    "applies it. Point source_config at a fixture holding at least "
                    "one row with id = 'test' to make this check bite.",
                    UserWarning,
                    stacklevel=2,
                )
            else:
                assert refuting.rows != matching.rows, (
                    "the adapter returned identical rows for id = 'test' and for "
                    f"id = {_NO_SUCH_VALUE!r}, so the constraint changed nothing. "
                    "Apply it, or raise ScopeEnforcementError."
                )
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
