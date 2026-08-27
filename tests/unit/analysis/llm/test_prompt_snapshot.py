"""Byte-for-byte prompt snapshot test for ``intent_v2.txt`` (Task 3.7).

FR-15 pins the intent-analysis prompt template at filename ``intent_v2.txt``
and requires every edit to force a visible ``prompt_version`` bump in the
audit stream. This test locks the template's SHA-256 so any silent edit —
whitespace, capitalization, reordered rules — breaks CI before a provider
ever talks to an LLM.

Bumping the prompt intentionally is a two-step change:

1. Rename the file to ``intent_v3.txt`` (or whatever the next version is).
2. Update the provider modules' ``_PROMPT_PATH`` / ``_PROMPT_VERSION`` and
   recompute + paste the new expected hash below.

The hash is taken over the raw on-disk bytes (no encoding / EOL
normalization) so cross-platform checkouts must either lock a single EOL
style via :file:`.gitattributes` or land matching hashes per platform. The
current hash was locked on the repo's committed bytes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

# SHA-256 of the on-disk bytes of ``nautilus/analysis/llm/prompts/intent_v2.txt``.
# Regenerate only when intentionally bumping the prompt version; see module docstring.
EXPECTED_INTENT_V2_SHA256: str = "e3d8155c977a9d61f7d96376cc430f21c5cc8f4b079ea55327c6aa1b6cc09535"

_PROMPT_PATH: Path = (
    Path(__file__).resolve().parents[4]
    / "nautilus"
    / "analysis"
    / "llm"
    / "prompts"
    / "intent_v2.txt"
)


@pytest.mark.unit
def test_intent_v2_prompt_sha256_locked() -> None:
    """``intent_v2.txt`` bytes hash to the locked SHA-256 (FR-15).

    Reads the file in binary mode so EOL conventions do not silently drift
    the hash between platforms.
    """
    assert _PROMPT_PATH.exists(), f"prompt template missing at {_PROMPT_PATH}"
    digest = hashlib.sha256(_PROMPT_PATH.read_bytes()).hexdigest()
    assert digest == EXPECTED_INTENT_V2_SHA256, (
        "intent_v2.txt has drifted from the locked snapshot. "
        "If the change is intentional, bump the prompt to intent_v3.txt and "
        "update EXPECTED_INTENT_V2_SHA256 accordingly.\n"
        f"  expected: {EXPECTED_INTENT_V2_SHA256}\n"
        f"  actual:   {digest}"
    )
