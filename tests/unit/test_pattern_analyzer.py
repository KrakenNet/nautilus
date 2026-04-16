"""Unit tests for :class:`nautilus.analysis.pattern_matching.PatternMatchingIntentAnalyzer`.

Covers the acceptance criteria called out by Task 3.3:

* **AC-2.2** — CVE regex extraction and keyword-map data-type coverage for the
  canonical ``"Find all known vulnerabilities, patches, and affected systems
  for CVE-2026-1234"`` intent (design §3.3).
* **AC-2.3** — An intent with zero keyword matches yields an empty
  ``data_types_needed`` list (and zero entities) — not an error.
* **Keyword-map from config** — the analyzer honours the exact mapping passed
  at construction time, independently of any hard-coded default.
* **AC-2.5 / NFR-13 determinism** — property-style test: 100 random intents,
  each analyzed 5 times, must produce bit-identical :class:`IntentAnalysis`
  model dumps. ``hypothesis`` is an optional dev dep, so this suite falls back
  to a seeded :mod:`random`-driven generator (``random.seed(42)``) that keeps
  the test hermetic and reproducible on every invocation.
"""

from __future__ import annotations

import random
import string

import pytest

from nautilus.analysis.pattern_matching import PatternMatchingIntentAnalyzer
from nautilus.core.models import IntentAnalysis

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------


def _default_keyword_map() -> dict[str, list[str]]:
    """The design §12 default keyword map used by AC-2.2 examples."""
    return {
        "vulnerability": ["vulnerability", "vuln"],
        "patch": ["patch", "fix"],
        "asset": ["asset", "system", "host"],
    }


# ---------------------------------------------------------------------------
# AC-2.2 — CVE extraction + data-type coverage
# ---------------------------------------------------------------------------


def test_ac_2_2_cve_extraction_and_data_types() -> None:
    """AC-2.2 — the canonical intent hits all three data types + the CVE entity."""
    analyzer = PatternMatchingIntentAnalyzer(_default_keyword_map())
    result = analyzer.analyze(
        "Find all known vulnerabilities, patches, and affected systems for CVE-2026-1234",
        {},
    )

    assert isinstance(result, IntentAnalysis)
    assert result.raw_intent.startswith("Find all known vulnerabilities")
    assert {"vulnerability", "patch", "asset"}.issubset(set(result.data_types_needed))
    assert "CVE-2026-1234" in result.entities


def test_ac_2_2_multiple_cve_ids_deduped_and_sorted() -> None:
    """Multiple CVE IDs are extracted, de-duplicated, and sorted alphabetically.

    Determinism (NFR-13) requires the entity list order be a pure function of
    content, which the implementation achieves via ``sorted(set(...))``.
    """
    analyzer = PatternMatchingIntentAnalyzer(_default_keyword_map())
    intent = (
        "Review vulnerabilities CVE-2024-0002, CVE-2023-1111, "
        "and CVE-2024-0002 again for the affected hosts"
    )
    result = analyzer.analyze(intent, {})

    assert result.entities == ["CVE-2023-1111", "CVE-2024-0002"]
    assert "vulnerability" in result.data_types_needed
    assert "asset" in result.data_types_needed


def test_cve_regex_ignores_malformed_ids() -> None:
    """Short-numbered / malformed CVE strings do not satisfy the regex.

    Pins the ``CVE-\\d{4}-\\d{4,}`` shape from ``pattern_matching._CVE_PATTERN``.
    """
    analyzer = PatternMatchingIntentAnalyzer(_default_keyword_map())
    result = analyzer.analyze("See CVE-99-1 and cve-2024-0001 (lowercase) in the report", {})

    assert result.entities == []


# ---------------------------------------------------------------------------
# AC-2.3 — zero match ⇒ empty list, not an error
# ---------------------------------------------------------------------------


def test_ac_2_3_zero_match_returns_empty_list() -> None:
    """AC-2.3 — no keyword hits ⇒ empty ``data_types_needed`` (and no crash)."""
    analyzer = PatternMatchingIntentAnalyzer(_default_keyword_map())
    result = analyzer.analyze("The weather today is pleasant and sunny.", {})

    assert result.data_types_needed == []
    assert result.entities == []
    assert result.raw_intent == "The weather today is pleasant and sunny."


def test_ac_2_3_empty_intent_returns_empty_lists() -> None:
    """The boundary case: the empty string must not raise or match anything."""
    analyzer = PatternMatchingIntentAnalyzer(_default_keyword_map())
    result = analyzer.analyze("", {})

    assert result.data_types_needed == []
    assert result.entities == []


# ---------------------------------------------------------------------------
# Keyword-map from config — analyzer honours the exact mapping it was given
# ---------------------------------------------------------------------------


def test_keyword_map_from_config_is_used_verbatim() -> None:
    """Only the configured data types can appear in the output.

    A bespoke mapping with a unique data-type name (``telemetry``) proves the
    analyzer does not consult any hard-coded default list.
    """
    custom_map = {
        "telemetry": ["ping", "heartbeat"],
        "inventory": ["sku", "part-number"],
    }
    analyzer = PatternMatchingIntentAnalyzer(custom_map)

    result = analyzer.analyze("Check the heartbeat for SKU A-100", {})

    assert set(result.data_types_needed) == {"telemetry", "inventory"}
    # Ensure the default vocabulary leaked nowhere.
    assert "vulnerability" not in result.data_types_needed


def test_keyword_matching_is_case_insensitive() -> None:
    """Per the analyzer docstring, keyword scanning is case-insensitive.

    Mixed-case keyword configs and mixed-case intents must both be matched.
    """
    analyzer = PatternMatchingIntentAnalyzer({"asset": ["Host", "System"]})
    result = analyzer.analyze("Inspect the HOST named alpha and the SYSTEM named beta", {})

    assert result.data_types_needed == ["asset"]


def test_data_types_needed_is_sorted_and_deduplicated() -> None:
    """Output ordering is deterministic: alphabetic, de-duplicated.

    Two keywords for the same data type must not produce duplicate entries,
    and two different data types must appear in sorted order regardless of
    the keyword-map iteration order.
    """
    # Insertion order deliberately anti-alphabetic to expose any accidental
    # reliance on dict iteration order.
    keyword_map = {
        "zeta": ["zz"],
        "alpha": ["aa"],
    }
    analyzer = PatternMatchingIntentAnalyzer(keyword_map)
    result = analyzer.analyze("aa zz aa", {})

    assert result.data_types_needed == ["alpha", "zeta"]


# ---------------------------------------------------------------------------
# NFR-13 / AC-2.5 — determinism property: 100 intents × 5 repeats identical
# ---------------------------------------------------------------------------


def _random_intent(rng: random.Random) -> str:
    """Generate a pseudo-intent blending keywords, noise, and (maybe) a CVE.

    The intent is built from a mix of real keywords (so ``data_types_needed``
    is usually non-empty), random filler tokens (lowercase + digits), and
    occasionally one or two CVE IDs. Whitespace and token ordering are
    randomised so repeated calls produce diverse inputs.
    """
    keyword_pool = [
        "vulnerability",
        "vuln",
        "patch",
        "fix",
        "asset",
        "system",
        "host",
    ]
    filler_alphabet = string.ascii_lowercase + string.digits

    tokens: list[str] = []
    for _ in range(rng.randint(3, 12)):
        if rng.random() < 0.4:
            tokens.append(rng.choice(keyword_pool))
        else:
            length = rng.randint(3, 8)
            tokens.append("".join(rng.choices(filler_alphabet, k=length)))

    # Sprinkle in 0..2 CVE IDs at random positions.
    for _ in range(rng.randint(0, 2)):
        year = rng.randint(1999, 2030)
        ordinal = rng.randint(1000, 99999)
        cve = f"CVE-{year}-{ordinal}"
        tokens.insert(rng.randint(0, len(tokens)), cve)

    return " ".join(tokens)


def test_nfr_13_determinism_100_intents_x_5_repeats() -> None:
    """NFR-13 / AC-2.5 — identical inputs always yield identical outputs.

    Generates 100 pseudo-random intents with a fixed seed, then re-analyzes
    each one five times. Every repeat must produce a byte-identical
    ``model_dump()`` and therefore an identical ``IntentAnalysis``.

    Using ``random.seed(42)`` (stdlib) keeps the suite hermetic: the property
    is reproducible on every CI run without depending on the optional
    ``hypothesis`` package (see task body).
    """
    analyzer = PatternMatchingIntentAnalyzer(_default_keyword_map())
    rng = random.Random(42)

    intents = [_random_intent(rng) for _ in range(100)]
    assert len(intents) == 100

    for intent in intents:
        baseline = analyzer.analyze(intent, {}).model_dump()
        for _ in range(5):
            repeat = analyzer.analyze(intent, {}).model_dump()
            assert repeat == baseline, (
                f"non-deterministic output for intent {intent!r}: {repeat!r} != {baseline!r}"
            )


def test_nfr_13_determinism_independent_of_context_dict_mutations() -> None:
    """Determinism extends to the ``context`` arg — it is ignored in Phase 1.

    The Protocol accepts ``context`` for forward-compat with the LLM-backed
    analyzer (AC-2.4), but the pattern-matcher must not let context content
    leak into the output. Two identical intents with wildly different
    contexts must still produce equal analyses.
    """
    analyzer = PatternMatchingIntentAnalyzer(_default_keyword_map())
    intent = "patch the vulnerable host"

    a = analyzer.analyze(intent, {})
    b = analyzer.analyze(intent, {"unrelated": "metadata", "nested": {"x": [1, 2, 3]}})

    assert a.model_dump() == b.model_dump()
