"""SSRF defenses shared across HTTP-based adapters (NFR-SSRF).

Mirrors the in-tree REST adapter helpers at
``nautilus/adapters/rest.py:202-223`` and ``:512-540`` so external adapter
packages (e.g. ``nautilus-adapter-nautobot``) do not import core modules.
"""

from __future__ import annotations

import ipaddress

import httpx

from .exceptions import AdapterError


class SSRFBlockedError(AdapterError):
    """Raised when a base URL or HTTP redirect points at a forbidden host."""


def reject_private_ip_literal(base_url: str) -> None:
    """Reject IP-literal base URLs pointing at private/loopback/link-local IPs.

    Hostname-based base URLs are NOT resolved here; per-request DNS pinning
    is out of scope. This check catches the common SSRF-via-config misstep:
    ``http://127.0.0.1``, ``http://169.254.169.254`` (cloud metadata), or
    RFC 1918 literals.
    """
    host = httpx.URL(base_url).host
    if not host:
        raise SSRFBlockedError(f"adapter requires a non-empty host in base_url {base_url!r}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # hostname — caller responsibility
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        raise SSRFBlockedError(f"adapter refuses private/loopback/link-local IP base URL: {host}")


def enforce_no_cross_host_redirect(response: httpx.Response, base_host: str) -> None:
    """Reject redirects that hop to a different host than the base URL.

    Only fires when ``response.history`` is non-empty (i.e. at least one
    redirect was followed). Examines the final response URL against the
    base host so an ``http://api.example.com`` config that ends at
    ``http://attacker.example.net`` raises rather than returning.
    """
    if not response.history:
        return
    final_host = response.url.host
    if final_host and final_host != base_host:
        raise SSRFBlockedError(
            f"adapter refuses cross-host redirect from {base_host!r} to {final_host!r}"
        )


__all__ = [
    "SSRFBlockedError",
    "enforce_no_cross_host_redirect",
    "reject_private_ip_literal",
]
