"""WAVE E19 — the compliance gate certified adapters that enforce nothing.

A scope constraint is a policy decision. The broker issues it, records it in
``BrokerResponse.scope_restrictions``, writes it to the audit entry, and signs it
into the attestation as a constraint that was applied. Then it hands the
constraint to the adapter and never looks at the returned rows again:
``Broker._gather_adapter_results`` bounds the response size and hashes the rows,
and does not compare a single row against ``state.scope_by_source``.

That is a deliberate boundary — the SDK contract is that an adapter applies the
constraint or raises ``ScopeEnforcementError`` for the operators it cannot — and
it makes ``AdapterComplianceSuite`` the only gate standing between a third-party
adapter and a signed receipt for enforcement that never happened.

``test_scope_enforcement_valid_operator`` asserted ``isinstance(result,
AdapterResult)``. That passes an adapter that accepts the constraint, ignores
it, and returns every row it has. The gate certified the exact failure it exists
to catch.

The shipped adapters are not the exposure: ``tests/journeys/test_routing_and_scope.py``
re-runs the equivalent query against Postgres and asserts the broker returned
exactly the allowed rows. The exposure is every adapter written against the SDK,
which the scaffold tells its author is compliant.
"""

from __future__ import annotations

import asyncio
import warnings
from typing import Any, ClassVar

import pytest

from nautilus.adapters.testing import AdapterComplianceSuite
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

pytestmark = [pytest.mark.unit]

_ROWS: list[dict[str, Any]] = [
    {"id": "test", "name": "alpha"},
    {"id": "other", "name": "bravo"},
]


class _IgnoresScope:
    """Takes the constraint, returns everything. The adapter the gate must fail."""

    source_type: ClassVar[str] = "ignores-scope"

    async def connect(self, config: SourceConfig) -> None:
        self._id = config.id

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        return AdapterResult(source_id=self._id, rows=list(_ROWS), duration_ms=0, error=None)

    async def close(self) -> None:
        return None


class _IgnoresScopeAndProjectsIdAway(_IgnoresScope):
    """The same breach, with ``id`` absent from the rows.

    A per-row predicate check alone cannot see this one: there is no ``id`` to
    contradict. It is caught by the constraint having changed nothing.
    """

    source_type: ClassVar[str] = "projects-id-away"

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        rows = [{"name": row["name"]} for row in _ROWS]
        return AdapterResult(source_id=self._id, rows=rows, duration_ms=0, error=None)


class _EmptyBackend(_IgnoresScope):
    """Ignores scope too, but returns nothing — so the check cannot discriminate.

    The declared ``rows`` on the config are what the *static* adapter would
    serve; this one never reads them, which is exactly the shape of a scaffolded
    adapter pointed at a backend the suite cannot seed.
    """

    source_type: ClassVar[str] = "empty"

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        return AdapterResult(source_id=self._id, rows=[], duration_ms=0, error=None)


def _suite(factory: Any) -> AdapterComplianceSuite:
    return AdapterComplianceSuite(
        adapter_factory=factory,
        source_config=SourceConfig(
            id="test-source",
            type="static",
            classification="unclassified",
            data_types=["generic"],
            rows=list(_ROWS),
        ),
    )


def test_e19_the_gate_fails_an_adapter_that_ignores_the_constraint() -> None:
    """The pin. An adapter returning unscoped rows must not be certified."""
    with pytest.raises(AssertionError) as excinfo:
        asyncio.run(_suite(_IgnoresScope).test_scope_enforcement_valid_operator())

    assert "contradict" in str(excinfo.value), (
        f"the failure has to say the rows contradicted the constraint, or an "
        f"adapter author cannot tell what to fix: {excinfo.value}"
    )


def test_e19_the_gate_fails_an_ignoring_adapter_that_returns_no_id() -> None:
    """The pin, second shape. No ``id`` to contradict, so nothing narrowed."""
    with pytest.raises(AssertionError) as excinfo:
        asyncio.run(
            _suite(_IgnoresScopeAndProjectsIdAway).test_scope_enforcement_valid_operator()
        )

    assert "changed nothing" in str(excinfo.value), str(excinfo.value)


def test_e19_a_real_enforcer_still_passes() -> None:
    """Control. The gate must reject non-enforcement, not every adapter."""
    from nautilus.adapters import StaticAdapter

    with warnings.catch_warnings():
        warnings.simplefilter("error")  # a vacuous pass would raise here
        asyncio.run(_suite(StaticAdapter).test_scope_enforcement_valid_operator())


def test_e19_an_empty_fixture_warns_instead_of_passing_in_silence() -> None:
    """Control. A scaffolded adapter points at a backend the suite cannot seed.

    Failing there teaches the author to delete the test, so the vacuous case
    warns and says what to do. It must not pass silently — that silence is how
    this defect survived.
    """
    with pytest.warns(UserWarning, match="could not verify scope enforcement"):
        asyncio.run(_suite(_EmptyBackend).test_scope_enforcement_valid_operator())
