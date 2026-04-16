"""Static grep guard against SQL-injection regressions in the adapter layer.

Implements Task 3.13 (NFR-4, design §13.1, §17 — SQL-injection risk row)
and Task 4.8 (AC-8.4 — extended per-adapter patterns for the Phase-2
Elasticsearch / Neo4j / REST / ServiceNow adapters).

Strategy
--------
Walk every ``.py`` file under ``nautilus/adapters/`` and scan it with a
5-line sliding window for the co-occurrence of an f-string and a DB-call
token (``execute`` / ``executemany`` / ``fetch`` / ``fetchrow`` /
``fetchval``). Additionally flag ``%s``-style formatting (``"..." % (...)``)
adjacent to a DB call. Either pattern is a regression signal: parameterized
queries go through ``$N`` placeholders exclusively (Task 2.8), so an
f-string sitting within five lines of a DB call is a prima-facie risk.

Phase-2 extension (Task 4.8)
----------------------------
Each of the four new adapters has its own sensitive-call token that would
admit injection if co-located with an f-string:

- ``elasticsearch.py`` — ``Search.query(`` / ``.query(`` (DSL query builder;
  values must flow through typed query objects, never strings).
- ``neo4j.py`` — ``execute_query(`` (Cypher driver; values must flow through
  ``parameters_=dict`` bindings).
- ``rest.py`` — literal ``f"{base_url}`` URL concatenation (values must flow
  through ``httpx.QueryParams`` / URL builder, never f-string concat).
- ``servicenow.py`` — ``_build_sysparm_query(`` / ``sysparm_query =`` /
  ``"sysparm_query"`` (encoded-query assembly; values must flow through the
  ``_sanitize_sn_value`` reject list).

A parametrized test (:func:`test_no_fstring_near_new_adapter_sensitive_calls`)
walks one adapter file per parameter so the failure message names the file.

Allowlist
---------
Lines tagged with a trailing ``# noqa: SQLGREP`` comment are excluded from
the scan. This is reserved for rare legitimate adjacency (e.g. a method
definition whose name happens to collide with the DB-call regex, or a
quoted-identifier SQL string that has already been hardened via
``quote_identifier``). Each such tag should carry a brief rationale.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# Canonical patterns — pinned verbatim by the task spec (§3.13). Do not edit.
FSTRING = re.compile(r"f['\"][^'\"]*\{[^}]+\}")
DBCALL = re.compile(r"\b(execute|executemany|fetch|fetchrow|fetchval)\s*\(")
# ``%s``-style formatting: either ``"..." % (...)`` or ``"..." % name`` where
# the format string contains an ``%s`` placeholder. The two sub-patterns
# match the two shapes the task spec calls out explicitly.
PERCENT_FORMAT = re.compile(r"['\"][^'\"]*%s[^'\"]*['\"]\s*%\s*[\(\w]")

WINDOW = 5
NOQA_TAG = "# noqa: SQLGREP"

_ADAPTERS_DIR = Path(__file__).resolve().parents[2] / "nautilus" / "adapters"


def _adapter_files() -> list[Path]:
    """Return every ``.py`` file under ``nautilus/adapters/`` (recursive)."""
    return sorted(p for p in _ADAPTERS_DIR.rglob("*.py") if p.is_file())


def _filter_lines(raw: list[str]) -> list[tuple[int, str]]:
    """Drop allowlisted lines; return ``(1-indexed-line-no, text)`` tuples.

    Filtering removes the line entirely from the scan so a ``# noqa: SQLGREP``
    tag on a method definition (e.g. ``async def execute(...)``) doesn't
    merely shift the window — it takes that line out of consideration.
    """
    kept: list[tuple[int, str]] = []
    for idx, line in enumerate(raw, start=1):
        if NOQA_TAG in line.rstrip():
            continue
        kept.append((idx, line))
    return kept


def _scan_file(path: Path) -> list[str]:
    """Return a list of violation messages for ``path`` (empty == clean)."""
    raw = path.read_text(encoding="utf-8").splitlines()
    filtered = _filter_lines(raw)
    violations: list[str] = []
    for i in range(len(filtered)):
        window = filtered[i : i + WINDOW]
        if len(window) < 2:
            # Need at least two lines to co-occur; single trailing line is safe.
            continue
        window_text = "\n".join(text for _lineno, text in window)
        start_lineno = window[0][0]
        if FSTRING.search(window_text) and DBCALL.search(window_text):
            violations.append(
                f"{path}:{start_lineno}: f-string within {WINDOW} lines of a "
                f"DB call (execute/fetch/...). Use $N placeholders or tag "
                f"the false-positive line with '{NOQA_TAG}'."
            )
        if PERCENT_FORMAT.search(window_text) and DBCALL.search(window_text):
            violations.append(
                f"{path}:{start_lineno}: '%s'-style formatting within "
                f"{WINDOW} lines of a DB call. Use $N placeholders."
            )
    return violations


@pytest.mark.unit
def test_no_fstring_or_percent_formatting_near_db_calls() -> None:
    """No adapter file interpolates into a SQL string near a DB call.

    Done-when (Task 3.13): 0 matches across ``nautilus/adapters/*.py``
    (after excluding lines tagged ``# noqa: SQLGREP``).
    """
    assert _ADAPTERS_DIR.is_dir(), f"adapter source tree not found at {_ADAPTERS_DIR}"
    files = _adapter_files()
    assert files, f"no .py files found under {_ADAPTERS_DIR}"

    all_violations: list[str] = []
    for path in files:
        all_violations.extend(_scan_file(path))

    assert not all_violations, "SQL-injection static grep guard failed:\n" + "\n".join(
        all_violations
    )


# ---------------------------------------------------------------------------
# Task 4.8: per-adapter sensitive-call scans
# ---------------------------------------------------------------------------

# Per-adapter sensitive-call tokens. Each entry maps an adapter filename to a
# regex matching the call site(s) that would admit injection if co-located
# with an f-string interpolation. The 5-line window and ``# noqa: SQLGREP``
# allowlist are shared with the Phase-1 guard above.
_ADAPTER_SENSITIVE_TOKENS: dict[str, re.Pattern[str]] = {
    # ES DSL ``Search.query(...)``; also catches ``search.query(`` /
    # ``AsyncSearch.query(`` / any ``.query(`` call on a Search-like object.
    "elasticsearch.py": re.compile(r"\b(Search|search)\s*\.\s*query\s*\("),
    # Neo4j driver ``execute_query(`` call site — Cypher injection surface.
    "neo4j.py": re.compile(r"\bexecute_query\s*\("),
    # ServiceNow encoded-query assembly: the builder method, its assignment,
    # or the literal ``"sysparm_query"`` request-param key.
    "servicenow.py": re.compile(r"_build_sysparm_query\s*\(|\bsysparm_query\s*=|\"sysparm_query\""),
}

# REST adapter is a special case: the anti-pattern (``f"{base_url}/..."``)
# is a single-line violation rather than a co-occurrence window. Any line
# interpolating ``base_url`` into an f-string URL is a direct injection
# signal (NFR-4, AC-9.3 — values must flow through ``httpx.QueryParams`` /
# URL builder, never string concatenation).
_REST_URL_CONCAT: re.Pattern[str] = re.compile(r"f['\"][^'\"]*\{\s*(?:self\._)?base_url\b")


def _scan_file_for_sensitive_token(path: Path, token: re.Pattern[str]) -> list[str]:
    """Return violations where an f-string co-occurs with ``token`` within WINDOW lines.

    Mirrors :func:`_scan_file` but parameterized over the sensitive-call regex
    so the four Phase-2 adapters can each plug in their own call site.
    """
    raw = path.read_text(encoding="utf-8").splitlines()
    filtered = _filter_lines(raw)
    violations: list[str] = []
    for i in range(len(filtered)):
        window = filtered[i : i + WINDOW]
        if len(window) < 2:
            continue
        window_text = "\n".join(text for _lineno, text in window)
        start_lineno = window[0][0]
        if FSTRING.search(window_text) and token.search(window_text):
            violations.append(
                f"{path}:{start_lineno}: f-string within {WINDOW} lines of "
                f"sensitive call matching /{token.pattern}/. Use typed "
                f"query/parameter binding or tag the false-positive line "
                f"with '{NOQA_TAG}'."
            )
    return violations


def _scan_rest_url_concat(path: Path) -> list[str]:
    """Return violations where any line concatenates into a URL via f-string.

    The REST adapter must route scope values through ``httpx.QueryParams``;
    an f-string interpolating ``base_url`` (or ``self._base_url``) is a
    prima-facie SSRF / injection risk (NFR-4, AC-9.3).
    """
    raw = path.read_text(encoding="utf-8").splitlines()
    violations: list[str] = []
    for lineno, line in enumerate(raw, start=1):
        if NOQA_TAG in line.rstrip():
            continue
        if _REST_URL_CONCAT.search(line):
            violations.append(
                f"{path}:{lineno}: manual URL concatenation via f-string "
                f"(base_url interpolation). Route scope through "
                f"``httpx.QueryParams`` or tag the line with '{NOQA_TAG}'."
            )
    return violations


@pytest.mark.unit
@pytest.mark.parametrize(
    "adapter_filename",
    sorted(_ADAPTER_SENSITIVE_TOKENS.keys()),
)
def test_no_fstring_near_new_adapter_sensitive_calls(adapter_filename: str) -> None:
    """No Phase-2 adapter co-locates an f-string with its sensitive call site.

    Done-when (Task 4.8): 0 matches across ``elasticsearch.py``, ``neo4j.py``,
    and ``servicenow.py`` (after excluding ``# noqa: SQLGREP`` lines). REST
    is covered by :func:`test_rest_adapter_no_url_fstring_concat` because its
    hazard shape is single-line rather than a co-occurrence window.
    """
    path = _ADAPTERS_DIR / adapter_filename
    assert path.is_file(), f"expected adapter module at {path}"
    token = _ADAPTER_SENSITIVE_TOKENS[adapter_filename]
    violations = _scan_file_for_sensitive_token(path, token)
    assert not violations, (
        f"SQL-injection static grep guard failed for {adapter_filename}:\n" + "\n".join(violations)
    )


@pytest.mark.unit
def test_rest_adapter_no_url_fstring_concat() -> None:
    """REST adapter never interpolates ``base_url`` into an f-string (AC-9.3)."""
    path = _ADAPTERS_DIR / "rest.py"
    assert path.is_file(), f"expected adapter module at {path}"
    violations = _scan_rest_url_concat(path)
    assert not violations, "REST URL-concat grep guard failed:\n" + "\n".join(violations)


@pytest.mark.unit
def test_patterns_are_canonical() -> None:
    """Pin the canonical regex patterns to catch accidental edits.

    The task spec (§3.13) requires the two patterns to be copied verbatim
    into the test file. This test asserts both patterns' ``.pattern``
    attributes match the pinned strings so a stealthy edit (e.g. weakening
    the DB-call set) fails loudly in CI.
    """
    assert FSTRING.pattern == r"f['\"][^'\"]*\{[^}]+\}"
    assert DBCALL.pattern == r"\b(execute|executemany|fetch|fetchrow|fetchval)\s*\("
