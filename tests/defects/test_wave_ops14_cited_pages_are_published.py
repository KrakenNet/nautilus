"""WAVE ops14 — the documentation named an authority the published site did not contain.

``docs/`` sent the reader to ``deploy/README.md`` six times as the authority for
operating a container — §5 for the mounts, §2.1 for the host layout, §11 and
§11.3 for working inside an image with no shell. Every one of those sections
existed and said the right thing. None of them was reachable: ``mkdocs.yml``
sets no ``docs_dir``, so it defaults to ``docs/`` and everything under
``deploy/`` is outside the built site. A reader with only the documentation was
told six times to consult a document the documentation does not have.

What that cost: ``docker kill -s HUP`` — the only way to reload a containerised
broker, because a container has no systemd and the distroless image has no
shell and no ``kill`` — appeared twice in the unpublished file and zero times in
``docs/``. An external executor given the documentation and told to reload a
container could not find it and wrote an entire sidecar container to work
around it.

So this holds the class, not those six citations: **every reference in ``docs/``
to another document in this repository has to land on a page the built site
publishes, at a section that exists.** Three forms count, because all three are
what the pages actually write:

* a Markdown link whose target is a ``.md`` file —
  ``[Deploying §5](deploying.md#5-volumes-and-mounts)``;
* a link into a section of the page itself — ``[§11.4](#114-what-you-cannot-do-from-inside)`` —
  which is how a reader moves around a 1 200-line guide;
* a repo-relative path named in prose — ```deploy/README.md``` §5 — which is how
  all six broken references were written, and which nothing else sees:
  ``mkdocs build --strict`` validates link targets but not fragments, and a path
  in a sentence is not a link at all.

Design decisions worth knowing:

* **"Published" is "a page in the nav mkdocs builds"**, resolved through
  mkdocs' own config loader rather than by assuming ``docs/``. The assumption
  is the defect: the site's contents are whatever ``docs_dir`` and ``nav`` say
  they are, and a file outside them is a dead end for anyone who does not also
  have the repository.
* **Only the pages the site publishes are read.** A draft nothing links to is
  not making a promise to a reader, and ``docs/comps/`` — local-only material,
  excluded in ``.git/info/exclude`` — is absent from a clean clone entirely.
* **Fenced blocks are skipped.** A transcript is a recording, not an
  instruction — ``docs/reference/cli.md`` prints a comment naming
  ``docs/getting-started.md`` inside one. Same split as
  ``test_wave_ops13_reload_reachable.py``'s bash-versus-console rule.
* **A prose path that names no file in the repository is skipped, not failed.**
  ``my-csv-adapter/README.md`` is a file the adapter tutorial tells the reader
  to *create*, and ``app/README.md`` is a path inside the image. The cost is a
  false negative: a reference to a document that was deleted outright reads the
  same as a filename in an example.
* **A ``§N`` written next to a reference is checked against the section it
  points at**, so the number in the sentence cannot drift away from the anchor
  under it. That is the rot ``tests/citation_lock.py`` locks for
  ``path.py:NNN`` citations, in the form the prose uses for documents.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import pytest
from markdown.extensions.toc import slugify
from mkdocs.config import (
    load_config,  # pyright: ignore[reportUnknownVariableType] - **kwargs in its signature
)
from mkdocs.structure.files import get_files
from mkdocs.structure.nav import get_navigation

pytestmark = pytest.mark.defect

REPO_ROOT = Path(__file__).resolve().parents[2]

_FENCE = re.compile(r"^\s*(?P<ticks>```+|~~~+)")
_HEADING = re.compile(r"^(?P<level>#{1,6})\s+(?P<title>.*?)\s*#*$")
_LINK = re.compile(r"\[(?P<text>[^\][]*)\]\((?P<target>[^)\s]+)\)")
#: A repo-relative document path named in prose: ``deploy/README.md``.  The
#: slash is required — a bare ``README.md`` is as often a file being described
#: as a document being cited.
_PROSE_PATH = re.compile(
    r"(?<![A-Za-z0-9_./-])(?P<path>[A-Za-z0-9_][A-Za-z0-9_./-]*/[A-Za-z0-9_.-]+\.md)"
)
_SECTION = re.compile(r"§\s*(?P<number>\d+(?:\.\d+)*)")
_NUMBERED = re.compile(r"^(?P<number>\d+(?:\.\d+)*)[.:]?\s")


@dataclass(frozen=True)
class Reference:
    """One place a page in ``docs/`` sends the reader to another document."""

    #: Repo-relative path of the citing page.
    page: str
    line: int
    #: What the page wrote, for the failure message.
    text: str
    #: Repo-relative path of the document referred to; ``""`` when the
    #: reference resolves to no file in the repository.
    target: str
    #: Fragment of a link target, without the ``#``; ``""`` when there is none.
    anchor: str
    #: The ``11.3`` of a ``§11.3`` written on the reference; ``""`` when absent.
    section: str


def _prose_ranges(text: str) -> list[tuple[int, int]]:
    """Character ranges of *text* that are neither fenced code nor link syntax."""
    fenced: list[tuple[int, int]] = []
    fence: str | None = None
    position = 0
    for line in text.splitlines(keepends=True):
        match = _FENCE.match(line)
        if match is not None:
            ticks = match.group("ticks")
            if fence is None:
                fence = ticks
            elif ticks[0] == fence[0] and len(ticks) >= len(fence):
                fence = None
        elif fence is None:
            fenced.append((position, position + len(line)))
        position += len(line)
    links = [match.span() for match in _LINK.finditer(text)]
    return [span for span in fenced if not any(lo <= span[0] < hi for lo, hi in links)]


def _headings(text: str) -> list[str]:
    """Heading titles, in order, ignoring anything inside a fenced block."""
    titles: list[str] = []
    fence: str | None = None
    for line in text.splitlines():
        match = _FENCE.match(line)
        if match is not None:
            ticks = match.group("ticks")
            if fence is None:
                fence = ticks
            elif ticks[0] == fence[0] and len(ticks) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        heading = _HEADING.match(line)
        if heading is not None:
            titles.append(heading.group("title"))
    return titles


def _anchors(text: str) -> dict[str, str]:
    """Anchor -> the numbered section it falls in (``""`` outside one).

    The anchor is what the ``toc`` extension mints for the heading, duplicates
    included, so this is the same identifier the built page carries.  The
    section is the nearest numbered heading at or above it, which is what a
    ``§N`` on a link into a sub-heading means.
    """
    minted: dict[str, int] = {}
    sections: dict[str, str] = {}
    current = ""
    for title in _headings(text):
        numbered = _NUMBERED.match(title)
        if numbered is not None:
            current = numbered.group("number")
        base = slugify(title, "-")
        seen = minted.get(base, 0)
        minted[base] = seen + 1
        sections[base if seen == 0 else f"{base}_{seen}"] = current
    return sections


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _section_number(text: str) -> str:
    """The ``11.3`` of a ``§11.3``, or ``""``."""
    match = _SECTION.search(text)
    return match.group("number") if match is not None else ""


def _resolve(page: str, path: str, *, relative_first: bool) -> str:
    """Map a written path onto one file in the repository, or ``""``.

    A link is relative to the page that carries it; a path written out in prose
    is written from the repository root.  Both are tried either way round —
    pages use both conventions — but the reference's own form goes first.
    """
    from_page = posixpath.normpath(posixpath.join(posixpath.dirname(page), path))
    order = [from_page, path] if relative_first else [path, from_page]
    return next((c for c in order if not c.startswith("..") and (REPO_ROOT / c).is_file()), "")


def _references_in(page: str, text: str) -> list[Reference]:
    """Every cross-document reference *page* makes, in both written forms."""
    found: list[Reference] = []

    for match in _LINK.finditer(text):
        target = match.group("target")
        if "://" in target:
            continue
        path, _, anchor = target.partition("#")
        # A bare fragment is a reference to a section of this same page, and
        # nothing checks those either: the reader who follows one into a
        # 1 200-line guide lands at the top of it.
        if not path.endswith(".md") and path:
            continue
        found.append(
            Reference(
                page=page,
                line=_line_of(text, match.start()),
                text=match.group(0),
                target=page if not path else _resolve(page, path, relative_first=True),
                anchor=anchor,
                section=_section_number(match.group("text")),
            )
        )

    ranges = _prose_ranges(text)
    for match in _PROSE_PATH.finditer(text):
        if not any(lo <= match.start() < hi for lo, hi in ranges):
            continue
        target = _resolve(page, match.group("path"), relative_first=False)
        if not target:
            # A path that names no file here is an example, not a citation.
            continue
        # The §N sits after the path and wraps with the paragraph, so the
        # window has to cross the line break: "`deploy/README.md`\n§11 is …".
        tail = text[match.end() : match.end() + 60]
        section = _SECTION.match(tail.lstrip("`\n\t "))
        start = text.rfind("\n", 0, match.start()) + 1
        found.append(
            Reference(
                page=page,
                line=_line_of(text, match.start()),
                text=text[start : text.find("\n", match.start())].strip(),
                target=target,
                anchor="",
                section=section.group("number") if section is not None else "",
            )
        )

    return found


@cache
def _published() -> frozenset[str]:
    """Repo-relative paths of the pages the built site's nav reaches.

    Read through mkdocs' own loader: ``docs_dir`` is configuration, and this
    check exists because it was assumed instead of read.
    """
    config = load_config(str(REPO_ROOT / "mkdocs.yml"))
    docs_dir = Path(config.docs_dir).resolve().relative_to(REPO_ROOT)
    navigation = get_navigation(get_files(config), config)
    return frozenset((docs_dir / page.file.src_uri).as_posix() for page in navigation.pages)


@cache
def _references() -> tuple[Reference, ...]:
    """Every cross-document reference the published pages make."""
    found: list[Reference] = []
    for page in sorted(_published()):
        found.extend(_references_in(page, (REPO_ROOT / page).read_text(encoding="utf-8")))
    return tuple(found)


def _where(reference: Reference) -> str:
    return f"{reference.page}:{reference.line}: {reference.text}"


def test_every_document_the_docs_send_a_reader_to_is_published() -> None:
    """The defect: six references to a document outside ``docs_dir``.

    A reader of the published site cannot open a file that is not in it, and
    neither can anyone handed the documentation without the repository.
    """
    references = _references()
    assert references, (
        "found no cross-document reference in docs/**.md — the extractor "
        "stopped matching, so this check is vacuous"
    )

    published = _published()
    unreachable = [_where(r) for r in references if r.target not in published]
    assert not unreachable, (
        f"{len(unreachable)} reference(s) in docs/ send the reader to a document the "
        f"built site does not publish. mkdocs.yml decides what the site contains: a "
        f"file outside docs_dir, or one no nav entry reaches, is a dead end for every "
        f"reader who does not also have this repository. Publish it, or stop citing "
        f"it: {unreachable}"
    )


def test_every_cited_section_anchor_exists() -> None:
    """A link into a section has to land on a heading that is there."""
    anchored = [r for r in _references() if r.anchor]
    assert anchored, (
        "found no reference into a section of another page — the extractor "
        "stopped matching, so this check is vacuous"
    )

    broken = [
        f"{_where(r)} -> no #{r.anchor} in {r.target}"
        for r in anchored
        if r.target in _published()
        and r.anchor not in _anchors((REPO_ROOT / r.target).read_text(encoding="utf-8"))
    ]
    assert not broken, (
        f"{len(broken)} reference(s) point at an anchor the target page does not mint. "
        f"mkdocs --strict does not check fragments; a link that lands at the top of a "
        f"long page has lost the paragraph it promised: {broken}"
    )


def test_a_section_number_names_the_section_it_points_at() -> None:
    """``§11.3`` has to be §11.3 of the document it is written next to."""
    numbered = [r for r in _references() if r.section and r.target in _published()]
    assert numbered, (
        "found no §N reference into another page — the extractor stopped "
        "matching, so this check is vacuous"
    )

    wrong: list[str] = []
    for reference in numbered:
        text = (REPO_ROOT / reference.target).read_text(encoding="utf-8")
        if reference.anchor:
            reached = _anchors(text).get(reference.anchor, "")
        else:
            numbers = {
                m.group("number") for m in map(_NUMBERED.match, _headings(text)) if m is not None
            }
            reached = reference.section if reference.section in numbers else ""
        if reached != reference.section and not reached.startswith(f"{reference.section}."):
            wrong.append(
                f"{_where(reference)} -> {reference.target} answers with "
                f"{f'§{reached}' if reached else 'no numbered section'}"
            )
    assert not wrong, (
        f"{len(wrong)} reference(s) name a section number that is not the section they "
        f"reach. The number in the sentence is a claim of its own, and renumbering the "
        f"target does not move it: {wrong}"
    )


def test_the_check_fires_on_a_reference_to_an_unpublished_document() -> None:
    """The guard: an extractor that stopped matching would pass all three.

    This is the shape the six broken references had, verbatim — a path in a
    sentence, a section number beside it, and a target the site does not carry.
    """
    page = "docs/how-to/operator-guide.md"
    text = "with no restart. `deploy/README.md`\n§11 is the full set: reading, listing.\n"
    references = _references_in(page, text)

    assert [(r.target, r.section, r.line) for r in references] == [("deploy/README.md", "11", 1)]
    assert references[0].target not in _published(), (
        "deploy/README.md is published now, so this guard is asserting nothing"
    )
