# Contributing to Nautilus

Thank you for your interest in contributing to Nautilus, a policy-first data broker for AI agents. All contributions are welcome — bug fixes, features, documentation, and feedback.

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Prerequisites

- **Python 3.13+**
- **[uv](https://docs.astral.sh/uv/)** — package and project manager
- **Docker** — required for integration tests only

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork:
   ```bash
   git clone https://github.com/<your-username>/nautilus.git
   cd nautilus
   ```
3. Install dependencies:
   ```bash
   uv sync --extra dev
   ```
4. Verify everything works:
   ```bash
   uv run pytest -m unit
   ```

## Finding Something to Work On

Browse the [issue tracker](https://github.com/KrakenNet/nautilus/issues) and look at the labels:

- **`good first issue`** — start here. Scoped work that needs no deep codebase knowledge.
- **`help wanted`** — issues where maintainers would welcome a contributor.
- **`needs-decision` / `needs-design`** — the approach or design isn't settled yet. Please don't open a PR for these; leave a comment with your thoughts instead.

For anything non-trivial, comment on the issue to say you're picking it up before you start, so we can avoid duplicate work.

## Development Workflow

### Branching

- Branch from `main`.
- Use descriptive branch names: `fix/rule-validation-error`, `feat/adapter-retry-logic`, `docs/api-reference`.

### Making Changes

1. Write your code and add tests for new functionality.
2. Run the linting and type-checking suite:
   ```bash
   uv run ruff check .
   uv run ruff format --check .
   uv run pyright
   ```
   `pyright` analyzes the whole tree, including modules that import the
   optional `otel` / LLM provider dependencies. Install those extras first so
   it can resolve every import:
   ```bash
   uv sync --extra dev --extra otel --extra llm-anthropic --extra llm-openai
   ```
3. Run tests:
   ```bash
   # Fast unit tests (no containers needed)
   uv run pytest -m unit

   # Integration tests (requires Docker)
   uv run pytest -m integration
   ```
4. Preview documentation changes:
   ```bash
   uv run mkdocs serve
   ```

## Pull Requests

- Keep PRs focused on a single change.
- Reference related issues (e.g., `Closes #42`).
- Fill out the PR template completely.
- All CI checks must pass before merge.
- Maintainers may request changes — this is collaborative, not adversarial.

## Releases and Version Numbers

There is exactly one version string: `[project] version` in `pyproject.toml`.
[release-please](https://github.com/googleapis/release-please) owns it — it opens
the bump PR, writes the `CHANGELOG.md` entry, and tags `vX.Y.Z` on merge.
Everything else derives from it:

- The build backend copies it into the installed distribution's metadata.
- `nautilus.__version__` reads that metadata back (`importlib.metadata`).
- `nautilus version`, `GET /healthz` and `info.version` in `GET /openapi.json`
  all report `nautilus.__version__`.

So do not hand-edit a version anywhere, and do not add a second literal — not in
a module, not in a README, not in a doc page. The one we used to keep in
`nautilus/__init__.py` drifted from `pyproject.toml` in 0.1.4 and needed a
follow-up commit to re-sync; there is now no second side to drift.

**A branch reports its own lineage, not the newest tag, and that used to rot
silently.** The version in the tree is whatever the last release commit *on this
branch* set. A long-lived branch cut before a release and never brought up to
date builds artifacts stamped with its fork point: this branch sat 76 commits
past `v0.2.2` while `v0.2.3`, `v0.2.4` and `v0.2.5` were tagged and on PyPI, so
everything it built called itself `0.2.2` — the same string as a released wheel
from months earlier. Two things now stop that:

- `tests/defects/test_wave_ops12_build_identity.py` goes red when the packaged
  version is not strictly ahead of **every** tag in the repository (or, on a
  commit that is itself tagged, is not equal to that tag). It is deliberately
  not a reachability rule: `v0.2.3`–`v0.2.5` are not ancestors of this branch,
  and a rule that only looked at reachable tags would have called `0.2.2`
  correct on the exact tree where it was colliding with a published wheel. On
  an unreleased tree the honest string is a `.devN` of the next version — the
  tree is `0.2.6.dev0` now. The check skips outside a git checkout (a wheel has
  no tags to compare against) and **fails, rather than skipping, in a checkout
  with no tags**, because `actions/checkout` fetches none by default and a
  skip there is how this rots again; `ci.yml` sets `fetch-tags: true`.
- A version cannot separate two builds of one release line, and is not asked
  to. The revision does: `docker build --build-arg BUILD_REV=…` stamps the
  revision into the image, and `GET /healthz` and `nautilus version` read it
  back out of the image. `.dockerignore` excludes `.git/`, so nothing inside the
  build can derive it; an image built without the argument reports `unknown` and
  never falls back to the version string. `NAUTILUS_BUILD_REV` is the same value
  for a checkout or a wheel, which carry no stamp — against a stamped image it is
  ignored and reported, because an identifier the command line can set is a
  property of the command line.

Still merge `main` before you cut a release branch. Two artifacts answering
`/healthz` with the same `version` *and* the same `build` but different
behaviour is a release-process bug; the same `version` and different `build` is
just a rollout in progress, which is what the field is for.

## Reporting Issues

- Use the provided issue templates when available.
- Include clear reproduction steps, expected behavior, and actual behavior.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead.

## Code Style

- **Formatting and linting**: Enforced by [ruff](https://docs.astral.sh/ruff/) with a line length of 100.
- **Type checking**: [pyright](https://github.com/microsoft/pyright) in strict mode. All public APIs must have type annotations.
- **Comments**: Don't state the obvious. Comment *why*, not *what*.

## Commit Messages

- Use imperative mood: "Add retry logic" not "Added retry logic".
- Keep the subject line concise (under 72 characters).
- Reference issues when applicable: "Fix rule cache invalidation (#15)".

## Sign-off (DCO)

Every commit must be signed off:

```bash
git commit -s -m "Add retry logic"
```

This appends `Signed-off-by: Your Name <you@example.com>` to the commit message, certifying you can legally contribute the code (full text: https://developercertificate.org/). The `DCO` check rejects PRs with unsigned commits.

**Forgot to sign off?** You don't need to rewrite history. When the `DCO` check fails it comments the exact one-line command to push a *remediation commit* — just run it and push. (`git rebase --signoff origin/main` also works.)

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
