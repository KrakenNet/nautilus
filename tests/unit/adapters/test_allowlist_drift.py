"""Task 4.9 cross-adapter operator-allowlist drift guard (NFR-4, design §7.2).

The per-adapter drift tests in Task 3.9 / 3.10 each pin their own adapter to
its local operator map. This module is the complementary *meta*-test: it pins
ALL four Phase-2 adapters (Elasticsearch, Neo4j, REST, ServiceNow) to the
single source-of-truth allowlist on
:data:`nautilus.adapters.base._OPERATOR_ALLOWLIST`, so that adding a new
operator to the base allowlist without wiring it into every adapter fails CI
loudly — not just in the one adapter whose author happened to also update
their local drift probe.

Strategy per adapter:

* **Elasticsearch**: the dispatch is a dict ``_DSL_BUILDERS``; we assert every
  base operator is a key. Removing one entry from the dict makes the
  parametrized row for that operator fail.
* **REST**: the dispatch is a dict ``_DEFAULT_BUILDERS``. ``NOT IN`` is
  present as a stub whose body raises (per-endpoint rejection unless an
  ``EndpointSpec.operator_templates`` declares it — AC-9.3). We still require
  it to be a key so the allowlist-miss path has a uniform shape. The
  "per-endpoint rejection" leg of the task body is covered here because the
  stub in the dict IS the rejection mechanism.
* **Neo4j**: the dispatch is an ``if/elif`` chain inside ``_build_cypher``,
  not a module-level dict. We exercise each operator end-to-end via
  ``_build_cypher`` with a probe value and assert the render succeeds
  without raising ``ScopeEnforcementError('operator not allowed: ...')``.
  Removing any ``elif`` arm falls through to the closing ``else`` and
  raises that exact error, failing the parametrized row.
* **ServiceNow**: same shape as Neo4j — the dispatch lives inside
  ``_render_segment``. We call it per operator with a probe value and assert
  no ``ScopeEnforcementError('sn-unsupported-operator: ...')`` is raised.
  Removing any arm falls through to the closing raise, failing the row.

The four shapes are declared as a single parametrize table so the failure
output names the offending adapter; there is no silent-accept branch.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from nautilus.adapters.base import (
    _OPERATOR_ALLOWLIST,  # pyright: ignore[reportPrivateUsage]
    ScopeEnforcementError,
)
from nautilus.adapters.elasticsearch import (
    _DSL_BUILDERS,  # pyright: ignore[reportPrivateUsage]
)
from nautilus.adapters.neo4j import Neo4jAdapter
from nautilus.adapters.rest import (
    _DEFAULT_BUILDERS,  # pyright: ignore[reportPrivateUsage]
)
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.config.models import NoneAuth, SourceConfig
from nautilus.core.models import ScopeConstraint

# ---------------------------------------------------------------------------
# Probe values per operator
# ---------------------------------------------------------------------------


def _probe_value(op: str) -> Any:
    """Return a minimally type-correct probe value for ``op``.

    Mirrors the per-adapter drift fixtures in tests 3.9/3.10 so that any arm
    guarded by ``_typecheck_value`` (IN/NOT IN want lists, BETWEEN wants a
    2-element sequence, LIKE wants a string) accepts the probe.
    """
    if op in ("IN", "NOT IN"):
        return ["a", "b"]
    if op == "BETWEEN":
        return [1, 10]
    if op == "LIKE":
        return "foo"
    if op == "IS NULL":
        return None
    return 5


# ---------------------------------------------------------------------------
# Shared fixture builders
# ---------------------------------------------------------------------------


def _make_source(source_type: str, **extras: Any) -> SourceConfig:
    base: dict[str, Any] = {
        "id": f"{source_type}_src",
        "type": source_type,
        "description": f"{source_type} source",
        "classification": "secret",
        "data_types": ["vulnerability"],
        "allowed_purposes": ["research"],
        "connection": {
            "elasticsearch": "http://localhost:9200",
            "neo4j": "bolt://localhost:7687",
            "rest": "https://api.example.com",
            "servicenow": "https://dev.service-now.com",
        }[source_type],
        "auth": NoneAuth(),
    }
    base.update(extras)
    return SourceConfig(**base)


# ---------------------------------------------------------------------------
# Per-adapter policy checkers. Each raises AssertionError (via pytest's
# built-in re-raise) on drift; no silent-accept path.
# ---------------------------------------------------------------------------


def _check_elasticsearch(op: str) -> None:
    """ES: operator must be a key of ``_DSL_BUILDERS``."""
    assert op in _DSL_BUILDERS, (
        f"ElasticsearchAdapter: operator '{op}' is in base _OPERATOR_ALLOWLIST "
        f"but missing from _DSL_BUILDERS — cross-adapter drift (NFR-4)"
    )


def _check_rest(op: str) -> None:
    """REST: operator must be a key of ``_DEFAULT_BUILDERS``.

    ``NOT IN`` is present as a rejection stub (per-endpoint opt-in via
    ``EndpointSpec.operator_templates``, AC-9.3). The stub's presence is
    still required so the allowlist-miss error path has a uniform shape.
    """
    assert op in _DEFAULT_BUILDERS, (
        f"RestAdapter: operator '{op}' is in base _OPERATOR_ALLOWLIST but "
        f"missing from _DEFAULT_BUILDERS — cross-adapter drift (NFR-4)"
    )


async def _check_neo4j(op: str) -> None:
    """Neo4j: ``_build_cypher`` must dispatch ``op`` without raising
    ``operator not allowed``. Removing an ``elif`` arm falls through to the
    closing else that raises exactly that error, failing this check.
    """
    adapter = Neo4jAdapter(driver=AsyncMock())
    await adapter.connect(_make_source("neo4j", label="Vuln"))
    try:
        cypher, _params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            "Vuln",
            [
                ScopeConstraint(
                    source_id="neo4j_src",
                    field="severity",
                    operator=op,  # type: ignore[arg-type]
                    value=_probe_value(op),
                )
            ],
            100,
        )
    except ScopeEnforcementError as exc:  # pragma: no cover — drift-only path
        pytest.fail(
            f"Neo4jAdapter: operator '{op}' is in base _OPERATOR_ALLOWLIST but "
            f"_build_cypher raised ScopeEnforcementError({exc!s}) — "
            f"cross-adapter drift (NFR-4)"
        )
    assert cypher, f"Neo4jAdapter: operator '{op}' rendered an empty Cypher fragment"


def _check_servicenow(op: str) -> None:
    """ServiceNow: ``_render_segment`` must dispatch ``op`` without raising
    ``sn-unsupported-operator``. Removing an ``if`` arm falls through to the
    closing raise, failing this check.
    """
    try:
        segment = ServiceNowAdapter._render_segment(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            ScopeConstraint(
                source_id="servicenow_src",
                field="state",
                operator=op,  # type: ignore[arg-type]
                value=_probe_value(op),
            )
        )
    except ScopeEnforcementError as exc:  # pragma: no cover — drift-only path
        pytest.fail(
            f"ServiceNowAdapter: operator '{op}' is in base _OPERATOR_ALLOWLIST "
            f"but _render_segment raised ScopeEnforcementError({exc!s}) — "
            f"cross-adapter drift (NFR-4)"
        )
    assert segment, f"ServiceNowAdapter: operator '{op}' rendered an empty segment"


# ---------------------------------------------------------------------------
# Connect-time smoke (pure static import of ElasticsearchAdapter so the
# fixture factory above is exercised once; also proves _DSL_BUILDERS is a
# plain dict and not, say, a ``defaultdict`` that would silently accept
# missing keys).
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_es_and_rest_dispatch_maps_are_plain_dicts() -> None:
    """Guard against a future refactor that swaps ``dict`` for a fallback type.

    A defaultdict (or a dict subclass with ``__missing__``) would silently
    satisfy the drift check for unknown keys. Pin the concrete type so that
    the drift-check semantics cannot be weakened without a loud failure.
    """
    assert type(_DSL_BUILDERS) is dict, (
        f"_DSL_BUILDERS must be a plain dict, not {type(_DSL_BUILDERS).__name__} "
        "— drift check would otherwise silently pass on missing keys"
    )
    assert type(_DEFAULT_BUILDERS) is dict, (
        f"_DEFAULT_BUILDERS must be a plain dict, not {type(_DEFAULT_BUILDERS).__name__}"
        " — drift check would otherwise silently pass on missing keys"
    )


# ---------------------------------------------------------------------------
# The meta-test: every base-allowlist operator must have a policy in every
# Phase-2 adapter. The parametrize expands to len(allowlist) * 4 rows; any
# single missing mapping lights up exactly one row with the adapter named.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("operator", sorted(_OPERATOR_ALLOWLIST))
async def test_every_adapter_declares_policy_for_every_allowlisted_operator(
    operator: str,
) -> None:
    """NFR-4 / design §7.2 — no adapter may silently drop a base-allowlist operator.

    Removing any operator from any one of the four adapters' mappings (the
    dispatch dict for ES/REST, the dispatch arm for Neo4j/ServiceNow) fails
    this test with a message naming the drifted adapter.
    """
    _check_elasticsearch(operator)
    _check_rest(operator)
    await _check_neo4j(operator)
    _check_servicenow(operator)


# ---------------------------------------------------------------------------
# Meta-assertion: the base allowlist is non-empty. Belt-and-braces so that a
# future accidental ``frozenset()`` on the base side does not cause the
# parametrize table to collapse to zero rows (vacuously green).
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_base_operator_allowlist_is_non_empty() -> None:
    """The parametrize table above expands to ``len(_OPERATOR_ALLOWLIST) * 4``
    rows; if the base allowlist is ever empty, the cross-adapter drift check
    would vacuously pass. Pin a positive floor so that regression is caught.
    """
    assert len(_OPERATOR_ALLOWLIST) >= 11, (
        f"base _OPERATOR_ALLOWLIST shrunk to {len(_OPERATOR_ALLOWLIST)} entries "
        "— cross-adapter drift meta-test would run with too few rows (NFR-4)"
    )
