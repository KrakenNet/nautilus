"""Wave E15 — the repo's own claims about itself have to be true.

``docs/comps/`` is local-only material (``.git/info/exclude``): competitive
comparison drafts that are not part of the published repo and are referenced by
neither ``mkdocs.yml`` nor ``mint.json``. So this whole module skips on a clean
clone rather than inventing a failure over files that were never shipped.

It earns its place where the drafts do exist. At HEAD every one of them claimed
"8 built-in adapters" and named eight, while ``ADAPTER_REGISTRY`` had ten --
``llm`` and ``static`` are both first-class, documented, registered source
types. Understating our own coverage is still being wrong, on the page where
being wrong costs the most.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from nautilus.adapters import ADAPTER_REGISTRY

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPS_DIR = REPO_ROOT / "docs" / "comps"

# The prose spells source types in product capitalisation, so the claim is
# checked against a spelling map rather than against the raw registry keys.
_PROSE_NAME = {
    "postgres": "PostgreSQL",
    "pgvector": "PgVector",
    "elasticsearch": "Elasticsearch",
    "neo4j": "Neo4j",
    "rest": "REST",
    "servicenow": "ServiceNow",
    "influxdb": "InfluxDB",
    "s3": "S3",
    "llm": "LLM",
    "static": "Static",
}

_COUNT_CLAIM = re.compile(r"\*{0,2}(\d+)\*{0,2}\s+built-in adapters", re.IGNORECASE)


def _comps_making_a_count_claim() -> list[Path]:
    if not COMPS_DIR.is_dir():
        return []
    return sorted(
        p for p in COMPS_DIR.glob("*.md") if _COUNT_CLAIM.search(p.read_text(encoding="utf-8"))
    )


_PAGES = _comps_making_a_count_claim()

pytestmark = pytest.mark.skipif(
    not _PAGES,
    reason="docs/comps/ is local-only material and is absent from this checkout",
)


def test_e15_the_spelling_map_still_covers_the_registry() -> None:
    """Control. A new source type fails here before the page tests go quiet.

    Without it, an adapter added to the registry and missing from the map would
    make the assertions below unenforceable rather than red.
    """
    assert set(ADAPTER_REGISTRY) == set(_PROSE_NAME), (
        "ADAPTER_REGISTRY and the prose spelling map have diverged; add the new "
        "source type to _PROSE_NAME and to every docs/comps page that counts them"
    )


@pytest.mark.parametrize("page", _PAGES, ids=lambda p: p.name)
def test_e15_a_comparison_page_states_the_real_adapter_count(page: Path) -> None:
    """The number on the page is the number in the registry."""
    match = _COUNT_CLAIM.search(page.read_text(encoding="utf-8"))
    assert match is not None  # guaranteed by the collector, asserted for the type checker
    claimed = int(match.group(1))
    assert claimed == len(ADAPTER_REGISTRY), (
        f"{page.relative_to(REPO_ROOT)} claims {claimed} built-in adapters; "
        f"ADAPTER_REGISTRY has {len(ADAPTER_REGISTRY)}: {sorted(ADAPTER_REGISTRY)}"
    )


@pytest.mark.parametrize("page", _PAGES, ids=lambda p: p.name)
def test_e15_a_comparison_page_names_every_adapter_it_counts(page: Path) -> None:
    """A count with a list beside it has to agree with the list.

    Bumping the number and leaving the parenthetical short would pass the count
    test and still mislead the reader, so the names are pinned separately.
    """
    text = page.read_text(encoding="utf-8")
    missing = [n for n in _PROSE_NAME.values() if not re.search(rf"\b{re.escape(n)}\b", text)]
    assert not missing, (
        f"{page.relative_to(REPO_ROOT)} counts built-in adapters but never names: {missing}"
    )
