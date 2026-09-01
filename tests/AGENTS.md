# AGENTS.md — tests

## Purpose

Prove that Nautilus does what it documents, and hold every confirmed 1.0 defect
red until its fix lands.

## Ownership

- `tests/journeys/` — one test per user-facing promise, end to end against a
  live backend. Green. A journey going red means a shipped promise broke.
- `tests/defects/` — one test per confirmed defect in the 1.0 audit
  (`REPORT.md`), the re-audit (`REAUDIT.md`) and the 1.0 readiness review.
  Red on purpose. Each fix flips a named test to green.
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
- The same goes for local-only material. `docs/comps/` is excluded in
  `.git/info/exclude` and is absent from a clean clone, so a test over it
  skips at module level rather than failing CI over files that never shipped.
  The citation lock enumerates docs through `git ls-files` for the same reason.
- **Never regenerate the citation lock to make the suite green.** Its whole job
  is to stop a code change from silently invalidating a line number a doc cites.
  A failure names the citation, the pages that carry it, the text it was locked
  against and the text now at that line; fix the number in the doc first,
  regenerate second.

## Verification

```bash
uv run pytest -m "not docker"   # fast lane, no containers (~40s)
uv run pytest -m docker         # live backends via testcontainers

python tests/citation_lock.py           # report drifted docs/ citations
python tests/citation_lock.py --write   # re-lock, once the citations are re-read
```

`docker` is applied automatically by `pytest_collection_modifyitems` in
`tests/conftest.py`, keyed on the backend fixtures a test requests. CI selects
with `-m "not docker"` — opt-out, so an untagged new test runs rather than
being silently skipped.

## Child DOX Index

None.
