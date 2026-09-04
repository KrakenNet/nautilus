"""Direct unit tests for the ``_is_loopback_host`` helper in ``nautilus.cli.serve``."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import pytest

from nautilus.cli.serve import _is_loopback_host

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://localhost:8000/x", True),
        ("http://localhost.:8000", True),
        ("http://127.0.0.1:8000", True),
        ("http://[::1]:8000", True),
        ("http://example.com", False),
        ("http://10.0.0.5", False),
        ("", False),
    ],
)
def test_is_loopback_host(url: str, expected: bool) -> None:
    """Loopback hosts and localhost resolve True; other hosts resolve False."""
    assert _is_loopback_host(url) is expected
