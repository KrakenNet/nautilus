# Nautilus docs orchestration

.PHONY: docs-build docs-serve docs-check docs-clean

# Strict build (fails on any warning)
docs-build:
	uv run mkdocs build --strict

# Local preview
docs-serve:
	uv run mkdocs serve

# All-in-one verification
docs-check: docs-build
	uv run python scripts/check_version_sync.py

docs-clean:
	rm -rf site/
