"""Unit tests for :func:`nautilus.core.clips_encoding.encode_multislot` (Task 2.3).

Verifies the CLIPS multislot encoding quoting rules (design §3.4, §5.1):
whitespace-bearing tokens are double-quoted so ``explode$`` /
``str.split`` round-trips them as a single token.
"""

from __future__ import annotations

import pytest

from nautilus.core.clips_encoding import encode_multislot


@pytest.mark.unit
def test_encode_multislot_quotes_whitespace_tokens() -> None:
    # Done-when: ``encode_multislot(["a b", "c"])`` returns ``'"a b" c'``.
    assert encode_multislot(["a b", "c"]) == '"a b" c'


@pytest.mark.unit
def test_encode_multislot_bare_tokens_unquoted() -> None:
    assert encode_multislot(["x", "y"]) == "x y"


@pytest.mark.unit
def test_encode_multislot_empty_or_none() -> None:
    assert encode_multislot(None) == ""
    assert encode_multislot([]) == ""


@pytest.mark.unit
def test_encode_multislot_escapes_embedded_quotes() -> None:
    # Embedded quote inside a whitespace-bearing token is backslash-escaped
    # so the quoted span remains well-formed for CLIPS explode$.
    assert encode_multislot(['a "b" c']) == '"a \\"b\\" c"'
