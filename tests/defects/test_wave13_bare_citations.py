"""Wave 13 — the citation shorthand the content lock cannot see, and one claim
about a value the code stopped producing.

``tests/citation_lock.py`` extracts ``path.py:NNN``. Pages routinely name the
path once and then continue with a bare ``:NNN`` on the same line — "``:72``,
``:104``" — and the extractor takes the first and drops the rest, so the
continuations are locked by nothing and rot in silence. A read-only sweep of
``docs/**.md`` at the parent commit found 61 such references, 30 of them
pointing at the wrong content. Extending the extractor would bring all 61 under
the lock; it would also land the suite red on 30 unrelated pages, so this module
pins the three that were fixed here and the count stays on the record.

The pins do not carry line numbers. Each names a *claim* — a message literal, a
class definition — and derives the lines that claim actually lives on from the
source, then requires the page's citations for it to be exactly those lines. A
citation fixed by arithmetic rather than by reading fails here the same as one
left alone.

The fourth and fifth defects are a different rot in the same page: this wave
replaced ``PostgresSessionStore._sanitized_dsn``'s partition-on-``@`` with
:func:`~nautilus.config.models.redact_connection`, an allowlist that copies out
scheme, host and port. The docs still described the old value — "the DSN with
its password stripped", a worked example carrying ``/nautilus``, and advice to
check ``sslmode`` from a message that can no longer contain a query parameter.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from nautilus.config.models import redact_connection

pytestmark = pytest.mark.defect

REPO_ROOT = Path(__file__).resolve().parents[2]

#: ``path.py:12``/``path.py:12-18``, and the bare ``:12`` continuation form.
_FULL = re.compile(
    r"(?<![A-Za-z0-9_./-])(?P<path>[A-Za-z0-9_][A-Za-z0-9_./-]*\.py):(?P<spec>\d+(?:-\d+)?)"
)
_BARE = re.compile(r"`:(?P<spec>\d+(?:-\d+)?)`")


def _section(doc: str, heading: str) -> str:
    """The body under *heading*, up to the next heading of any level."""
    text = (REPO_ROOT / doc).read_text(encoding="utf-8")
    start = text.index(heading) + len(heading)
    rest = text[start:]
    end = rest.find("\n#")
    return rest if end == -1 else rest[:end]


def _cited_lines(body: str, source: str) -> list[set[int]]:
    """One line set per citation in *body* that points at *source*.

    A bare ``:NNN`` inherits the path from the last full citation before it,
    which is what the shorthand means to a reader and what the lock's extractor
    does not do.
    """
    groups: list[set[int]] = []
    anchor: str | None = None
    for match in sorted([*_FULL.finditer(body), *_BARE.finditer(body)], key=lambda m: m.start()):
        path = match.groupdict().get("path")
        if path is not None:
            anchor = path
        if anchor is None or not source.endswith(anchor):
            continue
        lo, _, hi = match.group("spec").partition("-")
        groups.append(set(range(int(lo), int(hi or lo) + 1)))
    return groups


def _sites(source: str, claim: re.Pattern[str]) -> set[int]:
    lines = (REPO_ROOT / source).read_text(encoding="utf-8").splitlines()
    return {n for n, line in enumerate(lines, 1) if claim.search(line)}


CLAIMS = [
    pytest.param(
        "docs/reference/errors/sessions.md",
        "## The Postgres session store",
        "nautilus/core/session_pg.py",
        re.compile(r"^class (SessionSchemaError|SessionStoreUnavailableError)\b"),
        id="sessions-store-exception-classes",
    ),
    pytest.param(
        "docs/reference/errors/sessions.md",
        "### `PostgresSessionStore.aget() called before setup() succeeded`",
        "nautilus/core/session_pg.py",
        re.compile(r"PostgresSessionStore\.a(get|update)\(\) called before setup\(\) succeeded"),
        id="sessions-used-before-setup",
    ),
    pytest.param(
        "docs/reference/errors/transport.md",
        "### `Broker not ready`",
        "nautilus/transport/fastapi_app.py",
        re.compile(r'detail="Broker not ready"'),
        id="transport-broker-not-ready",
    ),
]


@pytest.mark.parametrize(("doc", "heading", "source", "claim"), CLAIMS)
def test_bare_continuation_citations_point_at_the_claim(
    doc: str, heading: str, source: str, claim: re.Pattern[str]
) -> None:
    """Every citation in the section covers a site, and every site is cited."""
    sites = _sites(source, claim)
    assert sites, f"{claim.pattern} matches nothing in {source}; the pin is vacuous"

    groups = _cited_lines(_section(doc, heading), source)
    assert groups, f"{doc} section {heading!r} cites {source} nowhere"

    missed = [sorted(g) for g in groups if not (g & sites)]
    assert not missed, (
        f"{doc} — {heading}: {len(missed)} citation(s) into {source} point at no line "
        f"matching {claim.pattern}: {missed}. Re-read them; do not renumber by arithmetic."
    )

    uncited = sorted(sites - set().union(*groups))
    assert not uncited, (
        f"{doc} — {heading}: {source} raises this at line(s) {uncited}, which the page "
        f"does not cite. A partial list reads as a complete one."
    )


def test_sanitized_dsn_examples_are_values_the_redactor_can_emit() -> None:
    """Every ``dsn=`` the docs show must be a fixed point of ``redact_connection``.

    ``_sanitized_dsn`` returns ``redact_connection(dsn)``, so the only strings
    that can appear after ``dsn=`` are ones the redactor would leave alone.
    ``postgresql://db.internal:5432/nautilus`` is not one: the path is dropped.
    """
    # Both message forms end the value the same way: ``)`` for the plain one,
    # ``: `` for the sqlite-fallback one that continues with ``{exc}``.  The
    # ``://`` is required so the unrendered ``dsn={self._sanitized_dsn()}`` in
    # the section headings is not mistaken for a value.
    shown = re.compile(
        r"PostgresSessionStore unavailable \(dsn="
        r"(?P<value>[A-Za-z][A-Za-z0-9+.-]*://[^)\s]+?)(?=\)|:\s)"
    )
    found: list[tuple[str, str]] = []
    for page in sorted((REPO_ROOT / "docs").rglob("*.md")):
        for match in shown.finditer(page.read_text(encoding="utf-8")):
            found.append((str(page.relative_to(REPO_ROOT)), match.group("value")))

    assert found, "no rendered PostgresSessionStore-unavailable example found in docs/"
    wrong = [
        (doc, value, redact_connection(value))
        for doc, value in found
        if redact_connection(value) != value
    ]
    assert not wrong, (
        "docs show a dsn= the code cannot produce (shown -> what redact_connection "
        f"would emit): {wrong}"
    )


def test_sanitized_dsn_entry_names_what_survives_and_not_what_does_not() -> None:
    """The entry has to describe the allowlisted value, not the old stripped one.

    ``sslmode`` is the specific trap: it is a query parameter, so it is exactly
    what this message stopped being able to show, and the entry used to end by
    telling the reader to check it.
    """
    body = _section(
        "docs/reference/errors/sessions.md",
        "### `PostgresSessionStore unavailable (dsn={self._sanitized_dsn()}): {exc}`",
    )
    dsn = "postgresql://user:pw@db.internal:5432/nautilus?sslmode=require"
    assert redact_connection(dsn) == "postgresql://db.internal:5432", (
        "redact_connection changed shape; this entry describes its output"
    )

    for survives in ("scheme", "host", "port"):
        assert survives in body, f"the entry does not say the message carries the {survives}"
    for dropped in ("database name", "query parameter"):
        assert dropped in body, f"the entry does not say the {dropped} is dropped"

    named = [para for para in body.split("\n\n") if "sslmode" in para]
    assert named, "the entry no longer tells the reader where sslmode has to be read"
    for para in named:
        assert "nautilus.yaml" in para, (
            "sslmode cannot be read off this message, so naming it without sending the "
            f"reader to nautilus.yaml is the old advice again: {para!r}"
        )
