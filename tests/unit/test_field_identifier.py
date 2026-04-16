"""Unit tests for field-identifier quoting and SQL-injection guards (Task 2.8).

The ralph-specum spec gate ``-k "field_identifier or sql_injection"`` selects
these tests. Together they pin the three Done-when requirements:

1. Field ``metadata.classification`` emits ``metadata->>'classification'``
   (JSONB text accessor, design §6.2).
2. Field ``valid_name`` emits ``"valid_name"`` (quoted identifier, NFR-4).
3. Field ``1bad`` raises :class:`ScopeEnforcementError` (regex guard).

Plus a dedicated SQL-injection probe that feeds an attack-style identifier
(embedded quote + ``DROP TABLE``) into both :func:`quote_identifier` and a
full ``_build_sql`` call, asserting both paths reject it before any SQL is
composed.
"""

from __future__ import annotations

import pytest

from nautilus.adapters.base import (
    ScopeEnforcementError,
    quote_identifier,
    render_field,
)
from nautilus.adapters.postgres import PostgresAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import ScopeConstraint


def _make_postgres_source() -> SourceConfig:
    return SourceConfig(
        id="vulns",
        type="postgres",
        description="vulnerability table",
        classification="secret",
        data_types=["vulnerability"],
        allowed_purposes=["research"],
        connection="postgres://localhost/vulns",
        table="vulns",
    )


# ---------------------------------------------------------------------------
# Done-when (1): dotted JSONB field emits the ``->>`` accessor.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_field_identifier_dotted_jsonb_emits_text_accessor() -> None:
    """``metadata.classification`` → ``"metadata"->>'classification'``.

    The quoted-parent wrapper is what defends against an attacker smuggling
    a reserved word or a trailing ``;`` through the parent segment; the child
    is regex-clean and rendered as a single-quoted SQL literal.
    """
    assert render_field("metadata.classification") == "\"metadata\"->>'classification'"


@pytest.mark.unit
def test_field_identifier_dotted_jsonb_appears_in_build_sql() -> None:
    """End-to-end: ``_build_sql`` splices the JSONB accessor verbatim.

    Proves the postgres adapter still emits ``metadata->>'classification'``
    (with the ``"`` wrapper around ``metadata``) after the quoting refactor.
    """
    adapter = PostgresAdapter(pool=object())
    adapter._config = _make_postgres_source()  # pyright: ignore[reportPrivateUsage]

    sql, _ = adapter._build_sql(  # pyright: ignore[reportPrivateUsage]
        table="vulns",
        scope=[
            ScopeConstraint(
                source_id="vulns",
                field="metadata.classification",
                operator="=",
                value="secret",
            )
        ],
        limit=100,
    )
    assert "\"metadata\"->>'classification'" in sql, f"JSONB accessor missing in {sql!r}"


# ---------------------------------------------------------------------------
# Done-when (2): plain identifier is wrapped in double quotes.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_field_identifier_plain_name_is_double_quoted() -> None:
    """``valid_name`` → ``"valid_name"`` via :func:`quote_identifier`."""
    assert quote_identifier("valid_name") == '"valid_name"'


@pytest.mark.unit
def test_field_identifier_plain_name_via_render_field() -> None:
    """:func:`render_field` routes plain idents through the same quoter."""
    assert render_field("valid_name") == '"valid_name"'


# ---------------------------------------------------------------------------
# Done-when (3): leading-digit identifier is rejected before SQL is composed.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_field_identifier_leading_digit_raises() -> None:
    """``1bad`` fails the §6.2 regex — ``ScopeEnforcementError``, not SQL."""
    with pytest.raises(ScopeEnforcementError):
        quote_identifier("1bad")


@pytest.mark.unit
def test_field_identifier_leading_digit_raises_via_render_field() -> None:
    """:func:`render_field` likewise refuses a leading-digit identifier."""
    with pytest.raises(ScopeEnforcementError):
        render_field("1bad")


@pytest.mark.unit
def test_field_identifier_leading_digit_raises_in_scope_constraint() -> None:
    """End-to-end: scope constraint with ``field="1bad"`` is rejected.

    ``ScopeConstraint`` itself accepts any string; the rejection must happen
    at ``_build_sql`` time before any f-string interpolation.
    """
    adapter = PostgresAdapter(pool=object())
    adapter._config = _make_postgres_source()  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(ScopeEnforcementError):
        adapter._build_sql(  # pyright: ignore[reportPrivateUsage]
            table="vulns",
            scope=[
                ScopeConstraint(
                    source_id="vulns",
                    field="1bad",
                    operator="=",
                    value="x",
                )
            ],
            limit=100,
        )


# ---------------------------------------------------------------------------
# SQL-injection probes — ensure the quoter + validator reject attacker input.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_sql_injection_attempt_with_embedded_quote_is_rejected() -> None:
    """``x"; DROP TABLE users; --`` must not reach SQL composition.

    The §6.2 regex forbids ``"``, ``;``, whitespace, and every non-identifier
    character. :func:`quote_identifier` calls :func:`validate_field` first,
    so the raise happens before the one-liner even runs ``.replace``.
    """
    with pytest.raises(ScopeEnforcementError):
        quote_identifier('x"; DROP TABLE users; --')


@pytest.mark.unit
def test_sql_injection_attempt_via_render_field_is_rejected() -> None:
    """Same attack vector through :func:`render_field`."""
    with pytest.raises(ScopeEnforcementError):
        render_field('x"; DROP TABLE users; --')


@pytest.mark.unit
def test_sql_injection_attempt_in_build_sql_raises_before_f_string() -> None:
    """A full scope constraint carrying an injection payload is rejected.

    If this ever stops raising, the f-string inside ``_build_sql`` would
    happily splice the attacker's ``"; DROP ...`` into the query. Failing
    this test means NFR-4 has regressed.
    """
    adapter = PostgresAdapter(pool=object())
    adapter._config = _make_postgres_source()  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(ScopeEnforcementError):
        adapter._build_sql(  # pyright: ignore[reportPrivateUsage]
            table="vulns",
            scope=[
                ScopeConstraint(
                    source_id="vulns",
                    field='x"; DROP TABLE users; --',
                    operator="=",
                    value="x",
                )
            ],
            limit=100,
        )


@pytest.mark.unit
def test_sql_injection_attempt_in_dotted_field_segment_is_rejected() -> None:
    """Dotted form with an injection in either segment must be rejected.

    The §6.2 regex matches the whole field at once, so a segment with a
    disallowed character fails the single-line check without needing a split.
    """
    with pytest.raises(ScopeEnforcementError):
        render_field('metadata."classification')

    with pytest.raises(ScopeEnforcementError):
        render_field("metadata.classification; DROP TABLE users")
