"""WAVE E16 — three claims the repo makes that are not true, found live.

1. **The contribution licence contradicts the licence.** ``LICENSE`` is
   Apache-2.0, ``pyproject.toml`` declares Apache-2.0 and the README says so
   three times. ``CONTRIBUTING.md`` tells every contributor their work is
   licensed under the *MIT License* — and links that phrase at the Apache file.
   Nobody who signed up to that agreed to what the repo actually ships under.

2. **The security policy declares the shipped version unsupported.**
   ``SECURITY.md`` lists ``0.1.x`` as the only supported series; the package is
   ``0.2.2``. A reporter reads that page to decide whether their version gets a
   fix, and it says no.

3. **The request model silently drops unknown top-level fields.**
   ``BrokerRequest`` is a plain pydantic ``BaseModel``, so ``extra`` defaults to
   ``ignore``. ``session_id`` and ``purpose`` belong in ``context``; sent at the
   top level -- the obvious shape, and the one I reached for first -- they are
   discarded without a word. The caller gets a fresh session on every request,
   so the cumulative exposure ledger never accumulates and its caps never trip,
   and the purpose they asked for is quietly replaced by the agent's default.
   ``nautilus/config/models.py`` already refuses unknown keys for exactly this
   reason: "Silence about a key that changes what runs is the opposite of the
   fail-closed handling the rest of the config" has. The API input is the same
   argument.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from pydantic import ValidationError

from nautilus import __version__
from nautilus.core.models import BrokerRequest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _declared_licence() -> str:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["license"])


def test_e16_contributing_names_the_licence_the_project_ships_under() -> None:
    """The licence a contributor agrees to is the licence in LICENSE."""
    declared = _declared_licence()
    text = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    section = text.split("## License", 1)[-1]
    assert "MIT" not in section, (
        f"CONTRIBUTING.md licenses contributions under MIT while pyproject.toml "
        f"declares {declared!r} and LICENSE is the Apache 2.0 text"
    )
    assert re.search(r"Apache(\s+License)?[-\s]?2(\.0)?", section), (
        f"CONTRIBUTING.md's License section does not name {declared!r}: {section.strip()[:200]!r}"
    )


def test_e16_the_licence_file_is_the_one_pyproject_declares() -> None:
    """Control. Pins which direction the test above is measuring from.

    If the project ever genuinely relicenses, this fails first and says so,
    rather than the CONTRIBUTING test failing and reading like a typo.
    """
    assert _declared_licence() == "Apache-2.0"
    assert "Apache License" in (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")


def test_e16_the_security_policy_covers_the_shipped_version() -> None:
    """The version people are running is listed as supported."""
    shipped_series = ".".join(__version__.split(".")[:2])
    policy = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    rows = re.findall(r"\|\s*(\d+\.\d+)\.x\s*\|", policy)
    assert rows, "SECURITY.md no longer has a `X.Y.x` supported-versions table"
    assert shipped_series in rows, (
        f"SECURITY.md supports {rows} but the shipped version is {__version__}; "
        f"the page tells a reporter their version gets no fix"
    )


@pytest.mark.parametrize("field", ["session_id", "purpose", "clearance"])
def test_e16_a_context_field_sent_at_the_top_level_is_refused(field: str) -> None:
    """A misplaced field that changes what runs is an error, not a shrug.

    All three belong in ``context``. Dropped in silence, ``session_id`` costs
    the caller their exposure ledger and ``purpose``/``clearance`` change which
    sources answer -- so the request succeeds and means something else.
    """
    with pytest.raises(ValidationError) as excinfo:
        BrokerRequest.model_validate(
            {"agent_id": "a", "intent": "show me orders", field: "whatever"}
        )
    assert field in str(excinfo.value), (
        f"the refusal must name {field!r} so the caller knows what to move into context"
    )


def test_e16_the_documented_request_body_still_validates() -> None:
    """Control. The four documented fields keep working, context included.

    Without this, deleting the model would pass every assertion above.
    """
    req = BrokerRequest.model_validate(
        {
            "agent_id": "intern",
            "intent": "show me recent orders",
            "context": {"session_id": "s1", "purpose": "monitoring", "clearance": "unclassified"},
            "fact_set_hash": None,
        }
    )
    assert req.context["session_id"] == "s1"
    assert req.context["purpose"] == "monitoring"
