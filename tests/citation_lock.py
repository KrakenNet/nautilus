#!/usr/bin/env python3
"""Content lock for the source-line citations in ``docs/``.

The documentation cites source by line number — ``nautilus/core/broker.py:1826``,
``nautilus/config/models.py:212-218``.  Nothing about such a citation breaks when
the code above it moves: the path still exists and the file is still long enough,
so a structural check passes on all of them while the numbers point at the wrong
statements.  That is not hypothetical here; it has happened repeatedly, most
recently when a 63-line insertion into ``fastapi_app.py`` silently invalidated 24
citations at once.

So this locks *content*, not structure.  For every citation it records a hash of
the line(s) currently cited, and ``tests/test_doc_citations.py`` fails when a
hash drifts.

What it deliberately does not do: parse the source, resolve symbols, or guess
where the cited code moved to.  Its entire answer is "citation X used to point at
this text and now points at that text — go look".  A human re-reads the citation,
fixes the number, and regenerates:

    .venv/bin/python tests/citation_lock.py --write

Design decisions worth knowing:

* **Lines are hashed stripped of leading and trailing whitespace.**  Wrapping a
  block in a ``try:`` or running a formatter re-indents code without changing
  what the citation claims, and a lock that fires on every reformat gets
  regenerated without anyone reading it, which is worse than no lock.  The cost
  is a false negative: a line moved into a different block but not otherwise
  edited passes.
* **A range citation hashes every line in the range, not just its endpoints.**
  The claim a range makes is about the whole block, and an in-place edit in the
  middle of a range leaves both endpoints intact.
* **Only files git tracks are scanned.**  ``docs/comps/`` is local-only
  (``.git/info/exclude``) and absent from a clean clone; locking citations from
  it would fail the suite everywhere but this machine.
* **A citation that cannot be resolved to exactly one file is recorded as
  unresolved, never dropped.**  Docs use a bare filename as shorthand once the
  page has named the path in full (``facts.py:46``, ``__init__.py:210``), so
  resolution tries the path as written, then a unique suffix match against
  tracked sources, then a unique suffix match against the full paths the citing
  page itself spells out.  Anything still ambiguous is locked as unresolved so it
  stays counted and visible rather than silently unchecked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import NotRequired, TypedDict


class Entry(TypedDict):
    """One citation as the lockfile records it."""

    citation: str
    cited_in: list[str]
    #: Absent when the citation could not be resolved to exactly one file.
    file: NotRequired[str]
    sha: NotRequired[str]
    #: Line number (as a string, because JSON) -> stripped source text, or
    #: ``None`` for a line past the end of the file.
    lines: NotRequired[dict[str, str | None]]
    unresolved: NotRequired[str]


class Lock(TypedDict):
    """The lockfile itself."""

    about: str
    regenerate: str
    citations: list[Entry]


REPO_ROOT = Path(__file__).resolve().parent.parent
LOCKFILE = Path(__file__).resolve().parent / "citations.lock.json"

#: ``some/path.py:12``, ``some/path.py:12-18``, ``some/path.py:12,18,30-33``.
CITATION_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"(?P<path>[A-Za-z0-9_][A-Za-z0-9_./-]*\.py)"
    r":(?P<spec>\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)"
)

#: A source path written out in full, with or without a line number.  Used only
#: to resolve a bare-filename shorthand against the same page's own prose.
QUALIFIED_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])[A-Za-z0-9_][A-Za-z0-9_./-]*/[A-Za-z0-9_]+\.py"
)

REGEN = "regenerate with: .venv/bin/python tests/citation_lock.py --write"


class GitUnavailableError(RuntimeError):
    """Raised when the tracked-file list cannot be read from git."""


def _tracked(root: Path) -> list[str]:
    """Repo-relative posix paths of every file git tracks."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            capture_output=True,
            check=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover - env
        raise GitUnavailableError(f"git ls-files failed in {root}: {exc}") from exc
    return [p for p in out.split("\0") if p]


def _spec_lines(spec: str) -> list[int]:
    """``"12,18-20"`` -> ``[12, 18, 19, 20]``, in citation order, deduplicated."""
    numbers: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            lo_text, hi_text = part.split("-", 1)
            lo, hi = int(lo_text), int(hi_text)
            span = range(lo, hi + 1) if lo <= hi else range(hi, lo + 1)
        else:
            span = range(int(part), int(part) + 1)
        numbers.extend(span)
    seen: set[int] = set()
    return [n for n in numbers if not (n in seen or seen.add(n))]


def _resolve(cited_path: str, py_files: list[str], hints: set[str]) -> tuple[str | None, str]:
    """Map a cited path onto one tracked file.

    Three rules, in order: the path as written from the repo root; a unique
    suffix match against tracked sources; and, for a shorthand too common to be
    unique repo-wide, a unique suffix match against the full paths the citing
    documents themselves spell out elsewhere (``__init__.py:210`` in a page whose
    prose says ``nautilus/cli/__init__.py``).  The third rule reads the
    document's own vocabulary; it never guesses at where code lives.

    Returns ``(path, reason)``; ``path`` is ``None`` when no rule lands on
    exactly one tracked file, and ``reason`` says why.
    """
    if cited_path in py_files:
        return cited_path, ""
    suffix = "/" + cited_path
    matches = [p for p in py_files if p.endswith(suffix)]
    if len(matches) == 1:
        return matches[0], ""
    if not matches:
        return None, "no tracked file has this path"
    from_docs = {p for p in hints if p.endswith(suffix)} & set(matches)
    if len(from_docs) == 1:
        return from_docs.pop(), ""
    return None, (
        f"{len(matches)} tracked files end with {cited_path!r} and the citing page(s) "
        f"name {len(from_docs)} of them in full; cite the path from the repo root"
    )


def digest(texts: list[str | None]) -> str:
    """Hash the cited content.  ``None`` marks a line past end-of-file."""
    payload = "\n".join("\x00past-eof" if t is None else t for t in texts)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def snapshot(root: Path = REPO_ROOT) -> Lock:
    """Build the lockfile body from the current working tree."""
    tracked = _tracked(root)
    py_files = [p for p in tracked if p.endswith(".py")]
    docs = sorted(p for p in tracked if p.startswith("docs/") and p.endswith(".md"))

    # citation text -> docs that cite it; doc -> full source paths its prose spells out
    found: dict[str, set[str]] = {}
    doc_paths: dict[str, set[str]] = {}
    for doc in docs:
        text = (root / doc).read_text(encoding="utf-8")
        for match in CITATION_RE.finditer(text):
            found.setdefault(match.group(0), set()).add(doc)
        doc_paths[doc] = set(QUALIFIED_PATH_RE.findall(text))

    source_cache: dict[str, list[str]] = {}
    entries: list[Entry] = []
    for citation in sorted(found):
        cited_path, spec = citation.rsplit(":", 1)
        citing = sorted(found[citation])
        entry = Entry(citation=citation, cited_in=citing)
        hints = doc_paths[citing[0]].intersection(*(doc_paths[d] for d in citing[1:]))
        resolved, reason = _resolve(cited_path, py_files, hints)
        if resolved is None:
            entry["unresolved"] = reason
            entries.append(entry)
            continue
        if resolved not in source_cache:
            source_cache[resolved] = (root / resolved).read_text(encoding="utf-8").splitlines()
        source = source_cache[resolved]
        numbers = _spec_lines(spec)
        texts = [source[n - 1].strip() if n <= len(source) else None for n in numbers]
        entry["file"] = resolved
        entry["sha"] = digest(texts)
        entry["lines"] = {str(n): t for n, t in zip(numbers, texts, strict=True)}
        entries.append(entry)

    return Lock(
        about="sha256 (truncated) of the whitespace-stripped source lines"
        " each docs/ citation points at",
        regenerate=REGEN,
        citations=entries,
    )


def _describe(entry: Entry) -> str:
    return f"{entry['citation']}  (cited in {', '.join(entry['cited_in'])})"


def _render_lines(entry: Entry) -> str:
    lines = entry.get("lines")
    if lines is None:
        return f"      <unresolved: {entry.get('unresolved')}>"
    return "\n".join(
        f"      {n}| {'<past end of file>' if t is None else t}" for n, t in lines.items()
    )


def check(lock: Lock, root: Path = REPO_ROOT) -> list[str]:
    """Compare *lock* against the working tree.  Returns one string per problem."""
    current = snapshot(root)
    locked = {e["citation"]: e for e in lock["citations"]}
    fresh = {e["citation"]: e for e in current["citations"]}

    problems: list[str] = []

    for citation in sorted(set(fresh) - set(locked)):
        problems.append(
            f"NEW, not locked: {_describe(fresh[citation])}\n"
            f"    it now points at:\n{_render_lines(fresh[citation])}\n"
            f"    Re-read it, then {REGEN}"
        )

    for citation in sorted(set(locked) - set(fresh)):
        problems.append(
            f"STALE lock entry: {citation} is no longer cited anywhere in docs/\n"
            f"    (it was cited in {', '.join(locked[citation]['cited_in'])})\n"
            f"    {REGEN}"
        )

    for citation in sorted(set(locked) & set(fresh)):
        old, new = locked[citation], fresh[citation]

        stored = old.get("lines")
        if stored is not None and digest(list(stored.values())) != old.get("sha"):
            problems.append(
                f"LOCKFILE EDITED BY HAND: {citation} — its sha does not match its own "
                f"recorded lines. {REGEN}"
            )
            continue

        if old.get("sha") == new.get("sha") and old.get("unresolved") == new.get("unresolved"):
            continue

        problems.append(
            f"DRIFTED: {_describe(new)}\n"
            f"    locked content:\n{_render_lines(old)}\n"
            f"    now points at:\n{_render_lines(new)}\n"
            f"    The code moved; the citation did not. Find where it went, fix the line "
            f"number in the doc, then {REGEN}"
        )

    return problems


def load(path: Path = LOCKFILE) -> Lock:
    body: Lock = json.loads(path.read_text(encoding="utf-8"))
    return body


def write(path: Path = LOCKFILE, root: Path = REPO_ROOT) -> list[Entry]:
    body = snapshot(root)
    path.write_text(json.dumps(body, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return body["citations"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite the lockfile from the working tree"
        " (do this only after re-reading the citations)",
    )
    parser.add_argument("--lockfile", type=Path, default=LOCKFILE)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    lockfile: Path = args.lockfile
    root: Path = args.root

    if args.write:
        entries = write(lockfile, root)
        unresolved = [e for e in entries if "unresolved" in e]
        print(
            f"locked {len(entries)} citations ({len(entries) - len(unresolved)} hashed,"
            f" {len(unresolved)} unresolved) -> {lockfile}"
        )
        for entry in unresolved:
            print(f"  unresolved: {entry['citation']} — {entry['unresolved']}", file=sys.stderr)
        # A citation whose every line is blank after stripping is pointing at
        # nothing.  The lock cannot tell whether that was always true, but it is
        # the one thing worth saying out loud at regeneration time.
        for entry in entries:
            lines = entry.get("lines")
            if lines and all(t == "" for t in lines.values()):
                print(
                    f"  points at a blank line, so it is already stale: {entry['citation']} "
                    f"(cited in {', '.join(entry['cited_in'])})",
                    file=sys.stderr,
                )
        return 0

    problems = check(load(lockfile), root)
    for problem in problems:
        print(problem, file=sys.stderr)
        print(file=sys.stderr)
    print(f"{len(problems)} problem(s)", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
