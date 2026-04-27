"""NFR-ATT-V2-FROZEN golden-file regression (spec nautilus-update-1 Task 8).

Freezes the v2 canonical output of
:func:`nautilus.core.attestation_payload.build_payload` for inputs that
DO NOT populate any of the three new fields the spec adds in Task 9
(``fact_set_hash``, ``cap_breached``, ``source_session_signatures``).

This test PASSES against current code (establishing the committed golden)
and MUST keep passing after Task 9 ships — proof that the
conditional-on-presence extension of ``_v2_canonical()`` is strict: the
canonical payload for a caller who does not populate any new field is
byte-identical to the pre-spec output (design §Cross-Cutting Concerns
Summary; requirements NFR-ATT-V2-FROZEN).

Fixtures:

- ``tests/fixtures/attestation/v2_frozen_input.json`` — hand-crafted
  ``build_payload`` input whose ``scope_constraints`` carries a non-empty
  temporal slot (so the v2 branch triggers) but carries NONE of the new
  fields. Because the pre-spec ``build_payload`` signature doesn't accept
  those fields at all, their absence is structurally guaranteed here.

- ``tests/fixtures/attestation/v2_frozen_expected.json`` — the
  byte-identical canonical JSON string (``sort_keys=True,
  separators=(",", ":")``) emitted by the pre-Task-9 ``_v2_canonical()``
  path, plus the parsed ``payload`` dict for readable failure diffs.

The assertion pins the canonical JSON string — any drift (key order,
separator whitespace, hash value, key addition/removal) flips the test
red immediately.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from nautilus.core.attestation_payload import build_payload

_FIXTURE_DIR: Path = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "attestation"
_INPUT_PATH: Path = _FIXTURE_DIR / "v2_frozen_input.json"
_EXPECTED_PATH: Path = _FIXTURE_DIR / "v2_frozen_expected.json"


def _load_json(path: Path) -> dict[str, Any]:
    assert path.exists(), f"Fixture missing at {path}"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.unit
def test_v2_frozen_canonical_payload_matches_golden() -> None:
    """Byte-identity gate: v2 canonical output frozen across the spec boundary.

    Loads the committed input fixture, re-runs ``build_payload()``, and
    asserts the canonical JSON string (``sort_keys=True,
    separators=(",", ":")``) equals the committed expected fixture. This
    is the NFR-ATT-V2-FROZEN regression — it must PASS today (establishing
    the golden) and MUST keep passing after Task 9 adds the three
    conditional-on-presence helpers.
    """
    raw_input = _load_json(_INPUT_PATH)
    expected = _load_json(_EXPECTED_PATH)

    payload, version = build_payload(
        request_id=raw_input["request_id"],
        agent_id=raw_input["agent_id"],
        sources_queried=list(raw_input["sources_queried"]),
        scope_constraints=raw_input["scope_constraints"],
        rule_trace=list(raw_input["rule_trace"]),
    )

    # Version gate: this fixture must route through the v2 branch — the
    # `expires_at` / `valid_from` slots are populated for precisely that
    # reason. If this flips to v1, the fixture has drifted or the
    # temporal-slot detection has regressed.
    assert version == "v2", f"expected v2 branch but got {version!r}"
    assert expected["version"] == "v2"

    # Primary byte-identity assertion — the NFR-ATT-V2-FROZEN gate.
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    assert canonical == expected["canonical"], (
        "v2 canonical payload drift detected — NFR-ATT-V2-FROZEN regression.\n"
        f"  committed golden: {expected['canonical']!r}\n"
        f"  current build_payload output: {canonical!r}\n"
        "If Task 9 intentionally changed this output, the fix is to first "
        "prove the change does NOT affect inputs that omit all three new "
        "fields; if it does, Task 9's conditional-on-presence is broken."
    )

    # Secondary sanity: the parsed dict also matches the golden dict. This
    # gives a readable structural diff when pytest renders the failure
    # (the canonical string comparison above is the byte-level gate; this
    # comparison is the human-debug aid).
    assert payload == expected["payload"]


@pytest.mark.unit
def test_v2_frozen_payload_omits_new_spec_keys() -> None:
    """Conditional-on-presence proof: none of the three new keys appear here.

    Task 9 adds three `_has_*()` guards that conditionally inject
    ``cost_cap_context`` / ``fact_set_hash`` / ``session_signatures`` into
    the v2 canonical payload. For inputs that do not populate any new
    field (like this fixture), the guards must all evaluate false and the
    payload must NOT contain those keys. Today this passes trivially
    because ``build_payload`` doesn't accept those inputs yet; after Task
    9 it continues to pass only if the guards are strict.
    """
    raw_input = _load_json(_INPUT_PATH)
    payload, _version = build_payload(
        request_id=raw_input["request_id"],
        agent_id=raw_input["agent_id"],
        sources_queried=list(raw_input["sources_queried"]),
        scope_constraints=raw_input["scope_constraints"],
        rule_trace=list(raw_input["rule_trace"]),
    )

    for forbidden in ("cost_cap_context", "fact_set_hash", "session_signatures"):
        assert forbidden not in payload, (
            f"v2 payload unexpectedly contains {forbidden!r} for an input "
            "that does not populate it — Task 9 conditional-on-presence is "
            "leaking new keys into the frozen v2 shape (NFR-ATT-V2-FROZEN)."
        )
