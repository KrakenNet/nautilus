# Nautilus docs orchestration

.PHONY: init docs-build docs-serve docs-check docs-clean

# Set up a local dev environment: install deps + pre-commit hooks
init:
	uv sync --all-extras
	uv run pre-commit install

# Strict build (fails on any warning)
docs-build:
	uv run mkdocs build --strict

# Local preview
docs-serve:
	uv run mkdocs serve

# All-in-one verification. ``scripts/check_version_sync.py`` used to run here
# and has not existed since 03abb25 -- so this target has failed on a missing
# file ever since. What it compared, pyproject.toml against a second version
# literal in nautilus/__init__.py, no longer has two sides: __version__ is read
# from the installed distribution's metadata.
docs-check: docs-build
	uv run python tests/citation_lock.py

docs-clean:
	rm -rf site/
