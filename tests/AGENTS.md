# AGENTS.md — tests

## Purpose

Prove that Nautilus does what it documents, and hold every confirmed 1.0 defect
red until its fix lands.

## Ownership

- `tests/journeys/` — one test per user-facing promise, end to end against a
  live backend. Green. A journey going red means a shipped promise broke.
- `tests/defects/` — one test per confirmed defect in the 1.0 audit
  (`REPORT.md`), the re-audit (`REAUDIT.md`), the 1.0 readiness review, the
  sealed `ops12` operator trials and the adversarial verification passes over
  the fix waves. Red on purpose. Each fix flips a named test to green.
  A finding is not a defect until it is reproduced here first-hand: two of the
  verification pass's own findings did not survive that, and one of them cited
  evidence that `git grep` disproved.
- `tests/unit/`, `tests/integration/` — pure-function and in-process tests for
  logic with no backend: scope-field validation, CLIPS encoding, hierarchy
  math, validators, config loading, replay sufficiency.
- `tests/backends.py` — the live-backend fixtures, shared by journeys and
  defect pins. A plain module, not a conftest: `pytest_plugins` is only
  honoured at the root, and root-level container fixtures would make the whole
  suite look as though it needs Docker.
- `tests/citation_lock.py` + `tests/citations.lock.json` — the content lock for
  the `path.py:NNN` source citations in `docs/`. A plain module and a checked-in
  lockfile, driven by `tests/test_doc_citations.py`.

## Local Contracts

- **Every test maps to a documented claim or a confirmed defect.** A test that
  pins an internal seam, a task number, or a file layout does not belong here.
- **Never assert against a mock of the thing under test.** The 1533-test suite
  this replaced missed all 120 audit findings largely because it asserted
  substrings of generated SQL and Flux against mocks, which pins the *broken*
  form as expected. Ask the backend.
- **Never configure the defect away.** The old Elasticsearch e2e test pinned a
  `keyword` mapping — the one mapping where the adapter works. Fixtures use
  default configuration, which is what a user gets.
- **Guard against vacuous passes.** An assertion that a forbidden row is absent
  also passes when the query returned nothing. Pair it with a control that
  proves the fixture works, or assert the exact expected set.
- **A red test must be red for its own reason.** Read the failure message
  before believing a pin; a fixture bug looks identical to a defect in the
  summary line.
- Container fixtures skip, never fail, when no Docker daemon is reachable.
- **`pyright` is at zero, not at a baseline.** A `# pyright: ignore[...]` has
  to name a reason a reader can check: the import ships no stubs
  (`testcontainers`, the un-installed half of aiobotocore's per-service
  overloads), or the name is private to another module in this repo. Anything
  the type system can be told instead — a widened return type, an `object`
  narrowed by `isinstance`, an annotated local — is told, not suppressed.
- **`fathom-rules` stays uncapped, so its private surface is guarded by a
  test.** `tests/defects/test_wave_e11.py` imports exactly what
  `nautilus/rkm/validator/static.py` imports, from the same modules —
  `Compiler` from `fathom.compiler`, `CompilationError` from `fathom.errors`.
  A version pin is not the guard; the test is.
- The same goes for local-only material. `docs/comps/` is excluded in
  `.git/info/exclude` and is absent from a clean clone, so a test over it
  skips at module level rather than failing CI over files that never shipped.
  The citation lock enumerates docs through `git ls-files` for the same reason.
- **A document the docs cite has to be a page the site publishes.**
  `tests/defects/test_wave_ops14_cited_pages_are_published.py` holds every
  reference a published page makes to another document — Markdown link, section
  link, or a repo-relative path named in prose — against the nav mkdocs builds,
  the anchors the target mints, and the `§N` the sentence claims. `mkdocs build
  --strict` checks none of the three: it validates link targets, not fragments,
  and a path written in a sentence is not a link.
- **Never regenerate the citation lock to make the suite green.** Its whole job
  is to stop a code change from silently invalidating a line number a doc cites.
  A failure names the citation, the pages that carry it, the text it was locked
  against and the text now at that line; fix the number in the doc first,
  regenerate second.
- **Relocate a drifted citation by content, never by arithmetic.** Take the
  text the lock recorded for each line and find where that text lives now; a
  `difflib` map is only trustworthy over its `equal` opcodes, because a line
  inside a `replace` span has no honest new home. Two attempts to renumber by
  span arithmetic turned 29 problems into 56.
- **Rewrite the numbers in one simultaneous pass.** Applying `A -> B` and then
  `B -> C` in separate passes sends `A` all the way to `C`, collapsing two
  distinct citations onto one range. **The lock cannot catch this**: it dedupes
  by citation string, so the survivor validates at 0 problems while the other
  reference silently names the wrong code. It happened, to two adjacent
  `DenialRecord` returns in `session-tokens.md`.
- **Audit the lockfile diff after `--write`.** Retired and added counts should
  match the number you moved, `lines` must not have changed for any citation
  you kept, and the total must not drop -- a citation count that falls by one
  is two references that collapsed onto each other.
- **Some docs publish a script *and its output*, and the output quotes line
  numbers.** `docs/how-to/hardening.md` embeds `logscan.py` and the rows it
  printed. Hand-editing those numbers makes the transcript a lie. Extract the
  script, run it, and paste what it actually printed — that also double-checks
  the relocation, from a source that never saw the lockfile.
- **The lock does not see the bare `:NNN` continuation form.** `CITATION_RE`
  matches `path.py:NNN`, so a page that names the path once and continues
  "`session_pg.py:72`, `:104`" has only its first reference locked. A sweep of
  `docs/**.md` counted 61 continuations, 30 of them pointing at the wrong
  content, so a green lock is not evidence that a page's later numbers are
  right — read them. `tests/defects/test_wave_ops12_bare_citations.py` pins the
  three that have been fixed, by deriving the correct lines from the source
  rather than recording them.

## Verification

```bash
uv run pytest -m "not docker"   # fast lane, no containers (~40s)
uv run pytest -m docker         # live backends via testcontainers
uv run pyright                  # zero errors; see the contract above

python tests/citation_lock.py           # report drifted docs/ citations
python tests/citation_lock.py --write   # re-lock, once the citations are re-read
```

`docker` is applied automatically by `pytest_collection_modifyitems` in
`tests/conftest.py`, keyed on the backend fixtures a test requests. CI selects
with `-m "not docker"` — opt-out, so an untagged new test runs rather than
being silently skipped.

## Child DOX Index

None.
