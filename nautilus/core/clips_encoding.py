"""CLIPS multislot encoding helpers (design §3.4, §5.1).

CLIPS slot types are restricted to ``string | symbol | float | integer``;
Nautilus encodes multi-valued fields (e.g. ``data_types``, ``entities``,
``allowed_purposes``) as a single space-separated string and rules explode
them back with ``explode$`` / Python ``str.split`` as needed.

This module isolates the quoting rules in one place so both the router and
any future fact producers share a single implementation.
"""

from __future__ import annotations


def encode_multislot(values: list[str] | None) -> str:
    """Encode a ``list[str]`` slot as a CLIPS-safe space-separated string.

    Quoting rules (design §5.4):

    - ``None`` or empty list → ``""`` (empty string).
    - Tokens without whitespace are emitted verbatim.
    - Tokens containing any whitespace are wrapped in double quotes so
      ``explode$`` / Python ``str.split`` reconstructs them as a single
      token; any embedded ``"`` is backslash-escaped.

    Examples:
        >>> encode_multislot(["a b", "c"])
        '"a b" c'
        >>> encode_multislot(["x", "y"])
        'x y'
        >>> encode_multislot(None)
        ''
    """
    if not values:
        return ""
    out: list[str] = []
    for raw in values:
        token = str(raw)
        if any(ch.isspace() for ch in token):
            # Quote the token so it survives split-on-whitespace round-trip.
            escaped = token.replace('"', '\\"')
            out.append(f'"{escaped}"')
        else:
            out.append(token)
    return " ".join(out)


__all__ = ["encode_multislot"]
