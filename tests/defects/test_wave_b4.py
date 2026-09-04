"""Two pins for Wave B4 — the trust boundary, written down where it is read.

Wave B4 is the §4 work of the readiness review. Both items are documentation,
and both are load-bearing: a grep for "trust boundary", "service credential"
or "sole enforcement" across ``docs/`` and the README returned exactly one
hit, and it was about adapter code execution. Everything Nautilus enforces
rests on assumptions — the broker is the only path to the sources, the source
credentials are the broker's and not the agent's, one deployment serves one
tenant — that nothing states, so nobody can check them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.defect

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_b4a_the_trust_boundary_is_written_down() -> None:
    """The assumptions every guarantee rests on must be stated somewhere.

    Nautilus decides what an agent may read and signs a receipt for it. That
    is worth nothing if the agent can reach the database directly, or if the
    source credentials are treated as the agent's own. Those are the load
    conditions on every other claim in the docs, and they were never written.
    """
    page = REPO_ROOT / "docs" / "concepts" / "trust-boundary.md"
    assert page.exists(), "docs/concepts/trust-boundary.md does not exist"
    text = page.read_text(encoding="utf-8").lower()

    for claim in (
        "sole enforcement point",
        "service credential",
        "reachable only by the broker",
    ):
        assert claim in text, f"the trust-boundary page never says {claim!r}"

    nav = (REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    assert "concepts/trust-boundary.md" in nav, "the page is not in the mkdocs nav"
    index = (REPO_ROOT / "docs" / "concepts" / "index.md").read_text(encoding="utf-8")
    assert "trust-boundary.md" in index, "the page is not linked from the concepts index"


def test_b4b_the_replica_section_says_a_deployment_is_one_tenant() -> None:
    """Two replicas share a ledger, a key ring and a rule set — and a tenant.

    "Running more than one replica" tells an operator how to scale a
    deployment out. Nothing on that page says the thing being scaled is
    single-tenant: the agent registry, the exposure ledger keyed on a derived
    principal, and the signing ring are all deployment-wide, so a second
    tenant means a second deployment, not a second replica.
    """
    guide = (REPO_ROOT / "docs" / "how-to" / "operator-guide.md").read_text(encoding="utf-8")
    start = guide.index("### Running more than one replica")
    end = guide.index("###", start + 10)
    section = guide[start:end].lower()
    assert "tenant" in section, (
        "the replica section never says a deployment is one tenant, so an "
        "operator scaling out has nothing telling them not to scale across"
    )
