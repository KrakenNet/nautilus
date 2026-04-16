"""Task 3.10 unit coverage for :mod:`nautilus.adapters.servicenow`.

Complements :mod:`tests.unit.adapters.test_servicenow_smoke` (Task 2.14)
with the five Task 3.10 cases called out by the spec:

(a) **Operator → encoded-query round-trip drift** — every operator in the
    base ``_OPERATOR_ALLOWLIST`` either renders to a recognisable
    GlideRecord segment or is explicitly unsupported by the SN adapter.
    Fails loud if the two drift apart (NFR-4).
(b) **``_sanitize_sn_value('bad^value')``** — ``ScopeEnforcementError`` with
    the exact ``'sn-injection-rejected'`` message (NFR-18).
(c) **Same for ``\\n`` and ``\\r``** — both newline bytes are rejected by
    the sanitiser with the same injection message.
(d) **httpx ``MockTransport`` end-to-end** — a scope with the full
    operator set composes into a single ``sysparm_query`` string whose
    segments are separated by ``^`` and match the encoded-query grammar.
(e) **OAuth refresh NOT supported** — the module exposes no
    refresh-token code path (surface-area negative assertion).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from nautilus.adapters.base import (
    _OPERATOR_ALLOWLIST,  # pyright: ignore[reportPrivateUsage]
    ScopeEnforcementError,
)
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.config.models import NoneAuth, SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_sn_source(
    table: str | None = "incident",
    connection: str = "https://dev.service-now.com",
) -> SourceConfig:
    return SourceConfig(
        id="sn_src",
        type="servicenow",
        description="SN incidents",
        classification="secret",
        data_types=["incident"],
        allowed_purposes=["research"],
        connection=connection,
        table=table,
        auth=NoneAuth(),
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="look up incidents",
        data_types_needed=["incident"],
        entities=[],
        temporal_scope=None,
        estimated_sensitivity=None,
    )


# ---------------------------------------------------------------------------
# (a) Operator → encoded-query drift (NFR-4)
# ---------------------------------------------------------------------------


# Maps each allowlisted operator to (value, expected ``sysparm_query`` segment).
# Centralising the mapping here means any new operator added to the base
# allowlist without a matching dispatch arm in ``_render_segment`` fails the
# drift test loudly (NFR-4).
_SN_DRIFT_PROBES: dict[str, tuple[Any, str]] = {
    "=": ("2", "state=2"),
    "!=": ("7", "state!=7"),
    "<": (3, "state<3"),
    ">": (3, "state>3"),
    "<=": (3, "state<=3"),
    ">=": (3, "state>=3"),
    "IN": (["1", "2"], "stateIN1,2"),
    "NOT IN": (["6", "7"], "stateNOT IN6,7"),
    "LIKE": ("network", "stateLIKEnetwork"),
    "BETWEEN": ([1, 5], "stateBETWEEN1@5"),
    "IS NULL": (None, "stateISEMPTY"),
}


@pytest.mark.unit
@pytest.mark.parametrize("operator", sorted(_OPERATOR_ALLOWLIST))
def test_operator_encoded_query_drift_every_op_renders(operator: str) -> None:
    """Every operator on the base allowlist produces a SN segment.

    Catches drift where a new operator lands in
    ``nautilus.adapters.base._OPERATOR_ALLOWLIST`` without a corresponding
    dispatch arm in ``ServiceNowAdapter._render_segment`` (NFR-4).
    """
    assert operator in _SN_DRIFT_PROBES, (
        f"operator '{operator}' in _OPERATOR_ALLOWLIST but missing from "
        f"_SN_DRIFT_PROBES — add a probe when extending the allowlist"
    )
    value, expected = _SN_DRIFT_PROBES[operator]
    segment = ServiceNowAdapter._render_segment(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        ScopeConstraint(
            source_id="sn_src",
            field="state",
            operator=operator,  # type: ignore[arg-type]
            value=value,
        )
    )
    assert segment == expected, (
        f"operator '{operator}' rendered '{segment}' but expected '{expected}' "
        "— drift between _OPERATOR_ALLOWLIST and _render_segment (NFR-4)"
    )


# ---------------------------------------------------------------------------
# (b) _sanitize_sn_value rejects '^' with the exact injection message (NFR-18)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_sanitize_sn_value_rejects_caret_with_exact_message() -> None:
    """``^`` triggers ``ScopeEnforcementError('sn-injection-rejected')``."""
    with pytest.raises(ScopeEnforcementError) as excinfo:
        ServiceNowAdapter._sanitize_sn_value("bad^value")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert str(excinfo.value) == "sn-injection-rejected"


# ---------------------------------------------------------------------------
# (c) Same for newline and carriage-return (NFR-18)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_value",
    ["line\nbreak", "carriage\rreturn"],
    ids=["newline", "carriage_return"],
)
def test_sanitize_sn_value_rejects_newline_chars_with_exact_message(
    bad_value: str,
) -> None:
    """``\\n`` and ``\\r`` both trigger the same injection rejection."""
    with pytest.raises(ScopeEnforcementError) as excinfo:
        ServiceNowAdapter._sanitize_sn_value(bad_value)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert str(excinfo.value) == "sn-injection-rejected"


# ---------------------------------------------------------------------------
# (d) httpx MockTransport end-to-end: full operator set composes one
#     sysparm_query with '^' separators (AC-11.2)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_full_operator_set_composes_caret_separated_sysparm_query() -> None:
    """A scope with the full operator surface composes one ``sysparm_query``.

    Uses :class:`httpx.MockTransport` so no live SN instance is contacted; the
    handler captures the outgoing URL and we round-trip the
    ``sysparm_query`` parameter back to the expected ``^``-joined string.
    """
    captured: dict[str, str] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"result": []})

    transport = httpx.MockTransport(_handler)
    client = httpx.AsyncClient(base_url="https://dev.service-now.com", transport=transport)
    adapter = ServiceNowAdapter(client=client)
    await adapter.connect(_make_sn_source())
    try:
        scope: list[ScopeConstraint] = [
            ScopeConstraint(source_id="sn_src", field="state", operator="=", value="2"),
            ScopeConstraint(source_id="sn_src", field="priority", operator="!=", value="7"),
            ScopeConstraint(
                source_id="sn_src",
                field="category",
                operator="IN",
                value=["network", "hardware"],
            ),
            ScopeConstraint(
                source_id="sn_src",
                field="short_description",
                operator="LIKE",
                value="outage",
            ),
            ScopeConstraint(
                source_id="sn_src",
                field="impact",
                operator="BETWEEN",
                value=[1, 3],
            ),
            ScopeConstraint(
                source_id="sn_src", field="resolved_at", operator="IS NULL", value=None
            ),
        ]
        await adapter.execute(intent=_intent(), scope=scope, context={})
    finally:
        await adapter.close()

    # Decode the captured URL's query string and recover sysparm_query.
    query_params = parse_qs(urlsplit(captured["url"]).query)
    assert "sysparm_query" in query_params, "sysparm_query absent from request"
    sysparm_query = query_params["sysparm_query"][0]

    expected_segments = [
        "state=2",
        "priority!=7",
        "categoryINnetwork,hardware",
        "short_descriptionLIKEoutage",
        "impactBETWEEN1@3",
        "resolved_atISEMPTY",
    ]
    assert sysparm_query == "^".join(expected_segments), (
        f"composed sysparm_query '{sysparm_query}' does not match the expected ^-joined segment set"
    )
    # Every segment is reachable via a '^' split (strict separator contract).
    assert sysparm_query.split("^") == expected_segments


# ---------------------------------------------------------------------------
# (e) OAuth refresh NOT supported — negative surface-area assertion
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_oauth_refresh_not_supported_no_related_code_path() -> None:
    """The adapter module exposes no refresh-token / OAuth2 symbols.

    This is a deliberate surface-area assertion: adding an OAuth refresh
    code path is a Phase-3+ decision that would need its own test and
    review, not a silent addition.
    """
    import nautilus.adapters.servicenow as sn_mod

    forbidden_substrings = ("refresh", "oauth2", "token_url", "token_endpoint")
    public_symbols = [name for name in dir(sn_mod) if not name.startswith("__")]
    offenders = [
        name for name in public_symbols for needle in forbidden_substrings if needle in name.lower()
    ]
    assert not offenders, (
        f"ServiceNow adapter module exposes OAuth-refresh-adjacent symbols "
        f"{offenders}; add an explicit test when introducing that code path"
    )

    # Also check the source bytes so a private helper / local variable with a
    # refresh-adjacent name is caught (cheap grep-equivalent over the module).
    import inspect

    source = inspect.getsource(sn_mod)
    source_lower = source.lower()
    for needle in ("refresh_token", "oauth2", "token_url", "token_endpoint"):
        assert needle not in source_lower, (
            f"ServiceNow adapter source contains '{needle}'; an OAuth refresh "
            "code path has been introduced without a dedicated test"
        )
