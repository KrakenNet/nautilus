# Contributing to Nautilus

Thank you for your interest in contributing to Nautilus, a policy-first data broker for AI agents. All contributions are welcome — bug fixes, features, documentation, and feedback.

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Prerequisites

- **Python 3.14+**
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

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
