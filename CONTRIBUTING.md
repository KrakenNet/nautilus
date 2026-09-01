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

**A branch reports its own lineage, not the newest tag, and that is a hazard.**
The version in the tree is whatever the last release commit *on this branch* set.
A long-lived branch cut before a release and never brought up to date builds
artifacts stamped with its fork point: at the time of writing, this branch is 70
commits past `v0.2.2` and does not contain `v0.2.3`, `v0.2.4` or `v0.2.5`, so
everything it builds calls itself `0.2.2` — the same string as a released wheel
from months earlier. Nothing in the code can fix that, because an installed
wheel genuinely cannot know it was built from an unreleased tree; do not try to
paper over it with a git-describe scheme, which only moves the lie into builds
that have no tag. Merge `main` before you cut a release branch, and treat two
artifacts answering `/healthz` with the same version but different behaviour as
a release-process bug, not a runtime one.

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

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
