"""Every source-line citation in ``docs/`` still points at the line it was read from.

The reference pages make a claim per citation — "this message is raised at
``nautilus/core/broker.py:1826``" — and a reader who follows one to the wrong
statement has been told something false.  Those claims rot silently: inserting
code above a cited line leaves the path valid and the file long enough, so
nothing structural notices.  Four separate passes over this repo have found and
hand-fixed a batch of such citations; the last one repaired 26, of which 24 had
been broken by a 63-line insertion in the same change.

``tests/citations.lock.json`` records what each citation pointed at when a human
last read it.  This test recomputes those hashes.  It does not know or care where
the code moved to — a failure means "go read the citation again", and once you
have::

    .venv/bin/python tests/citation_lock.py --write
"""

from __future__ import annotations

import pytest

from tests import citation_lock


def test_docs_citations_still_point_at_the_locked_source() -> None:
    if not citation_lock.LOCKFILE.exists():  # pragma: no cover - the lockfile ships
        pytest.fail(f"{citation_lock.LOCKFILE} is missing; {citation_lock.REGEN}")
    try:
        problems = citation_lock.check(citation_lock.load())
    except citation_lock.GitUnavailableError as exc:  # pragma: no cover - env
        pytest.skip(f"cannot list tracked docs: {exc}")

    assert not problems, "\n\n".join(
        [f"{len(problems)} docs citation(s) no longer match the lockfile:", *problems]
    )


def test_lock_reports_a_citation_whose_source_line_moved() -> None:
    """The guard itself: shift a cited line and the checker must name it.

    Without this, a checker that silently resolved nothing would pass the test
    above forever.
    """
    root = citation_lock.REPO_ROOT
    lock = citation_lock.load()
    entries = lock["citations"]
    victim = next(e for e in entries if e.get("lines") and e.get("file"))
    lines = victim.get("lines") or {}

    # Same citation, but locked against the content of some other line in the
    # same file — exactly what an insertion above the citation produces.
    source = (root / (victim.get("file") or "")).read_text(encoding="utf-8").splitlines()
    elsewhere = next(
        text for text in (s.strip() for s in source) if text and text not in lines.values()
    )
    moved = citation_lock.Entry(**victim)
    moved["lines"] = dict.fromkeys(lines, elsewhere)
    moved["sha"] = citation_lock.digest(list(moved["lines"].values()))
    tampered = citation_lock.Lock(
        about=lock["about"],
        regenerate=lock["regenerate"],
        citations=[moved if e is victim else e for e in entries],
    )

    problems = citation_lock.check(tampered)
    assert len(problems) == 1, problems
    assert victim["citation"] in problems[0]
    assert elsewhere in problems[0]
    for doc in victim["cited_in"]:
        assert doc in problems[0]
