"""``nautilus health`` subcommand."""

from __future__ import annotations

import sys
import urllib.error
import urllib.request

_DEFAULT_HEALTH_URL = "http://localhost:8000/readyz"
_HEALTH_TIMEOUT_S = 5


def _cmd_health(url: str) -> int:
    """Issue a GET against ``url`` with a 5s timeout. Exit 0 on HTTP 200."""
    try:
        with urllib.request.urlopen(url, timeout=_HEALTH_TIMEOUT_S) as resp:  # noqa: S310 - operator-controlled URL
            status = int(resp.status)
            if status == 200:
                print(f"OK {status} {url}")
                return 0
            print(f"FAIL {status} {url}", file=sys.stderr)
            return 1
    except urllib.error.HTTPError as exc:
        print(f"FAIL {exc.code} {url}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"FAIL unreachable {url}: {exc}", file=sys.stderr)
        return 1


__all__ = ["_DEFAULT_HEALTH_URL", "_cmd_health"]
