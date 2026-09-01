"""WAVE E28 -- the CLI took its broker credential only from ``argv``.

Every subcommand that talks to a running broker -- ``adapters list --url``,
``key list|rotate|revoke``, ``rkm queue approve`` -- accepted its ``X-API-Key``
as ``--api-key KEY`` and nowhere else. A credential in ``argv`` is not a secret
on a shared host::

    $ nautilus adapters list --url http://10.255.255.1:1 --api-key 953c9ec0... &
    $ ps -eo args | grep -- --api-key
    .../nautilus adapters list --url http://10.255.255.1:1 --api-key 953c9ec0...
    $ ls -l /proc/$!/cmdline /proc/$!/environ
    -r--r--r-- 1 sean sean 0 Sep  1 15:01 /proc/3975279/cmdline
    -r-------- 1 sean sean 0 Sep  1 15:01 /proc/3975279/environ

``cmdline`` is mode 444 -- readable by *every* account on the box -- while
``environ`` is 400. That difference is the whole fix: the credential may now
arrive in ``NAUTILUS_API_KEY``, resolved once in
:func:`nautilus.cli._common.resolve_api_key` so no subcommand can forget it.
``--api-key`` is unchanged and still wins, because it is a reasonable thing to
pass on a host nobody else logs into and every existing script passes it.

The pins are written against a real broker over a real socket rather than a
mocked transport: the claim is that the *server* accepts what the CLI sent, and
a mock of the header would pin whatever the CLI happens to build.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

KEY = "e28e28e28e28e28e28e28e28e28e28e2"
CONFIG = """
sources:
  - id: orders
    type: static
    classification: unclassified
    data_types: [orders]
    rows:
      - {{order_id: 1001, total: 19.99}}
agents:
  agent-alpha:
    id: agent-alpha
    clearance: confidential
api:
  keys:
    - "{key}"
session_tokens:
  enabled: true
"""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def broker(tmp_path_factory: pytest.TempPathFactory):
    """A live broker on a loopback port, gated by one known API key."""
    work = tmp_path_factory.mktemp("e28")
    (work / "nautilus.yaml").write_text(CONFIG.format(key=KEY), encoding="utf-8")
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if k != "NAUTILUS_API_KEY"}
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "nautilus.cli",
            "serve",
            "--config",
            str(work / "nautilus.yaml"),
            "--bind",
            f"127.0.0.1:{port}",
        ],
        cwd=work,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                pytest.fail(f"broker exited {proc.returncode} before becoming ready")
            try:
                if httpx.get(f"{url}/readyz", timeout=1.0).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.3)
        else:
            pytest.fail("broker never became ready")
        yield url
    finally:
        proc.terminate()
        proc.wait(timeout=15)


def _run(url: str, *args: str, env_key: str | None = None) -> subprocess.CompletedProcess[str]:
    """``nautilus <args> --url <url>`` with ``NAUTILUS_API_KEY`` set or removed."""
    env = {k: v for k, v in os.environ.items() if k != "NAUTILUS_API_KEY"}
    if env_key is not None:
        env["NAUTILUS_API_KEY"] = env_key
    return subprocess.run(
        [sys.executable, "-m", "nautilus.cli", *args, "--url", url],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def test_no_credential_anywhere_is_still_refused(broker: str) -> None:
    """The control. Without the flag and without the variable, the broker says no.

    Without this the three tests below would pass against a broker that
    authenticates nobody.
    """
    result = _run(broker, "adapters", "list")
    assert result.returncode == 1, result.stderr
    assert "401" in result.stderr


def test_adapters_list_reads_the_environment(broker: str) -> None:
    """``adapters list`` authenticates from ``NAUTILUS_API_KEY`` with no flag."""
    result = _run(broker, "adapters", "list", "--json", env_key=KEY)
    assert result.returncode == 0, result.stderr
    assert [r["id"] for r in json.loads(result.stdout)] == ["orders"]


def test_key_rotate_reads_the_environment(broker: str) -> None:
    """``key rotate`` -- a different module, the same resolver, no flag.

    ``rotate`` rather than ``list``: ``key list`` reads
    ``GET /v1/keys/jwks.json``, which is deliberately un-gated, so it answers
    with or without a credential and would pass whatever the CLI sent.
    ``POST /v1/keys/rotate`` is behind the key gate, and the control below
    proves it.
    """
    env = {k: v for k, v in os.environ.items() if k != "NAUTILUS_API_KEY"}
    env["NAUTILUS_REVIEWER"] = "e28@example.com"
    argv = [sys.executable, "-m", "nautilus.cli", "key", "rotate", "--yes", "--url", broker]

    refused = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)
    assert refused.returncode == 2, refused.stdout
    assert "401" in refused.stderr

    env["NAUTILUS_API_KEY"] = KEY
    accepted = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)
    assert accepted.returncode == 0, accepted.stderr
    assert accepted.stdout.startswith("OK: rotated: new primary kid=")


def test_rkm_approve_reads_the_environment(broker: str) -> None:
    """``rkm queue approve`` gets past authentication on the variable alone.

    The proposal does not exist, so the interesting answer is *which* refusal
    comes back: ``not found`` means the credential was accepted, and the 401 in
    the control case above means it would not have been without one.
    """
    env = {k: v for k, v in os.environ.items() if k != "NAUTILUS_API_KEY"}
    env["NAUTILUS_API_KEY"] = KEY
    env["NAUTILUS_REVIEWER"] = "e28@example.com"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "nautilus.cli",
            "rkm",
            "queue",
            "approve",
            "prop_absent",
            "--url",
            broker,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert "401" not in result.stderr, result.stderr
    assert "not found" in result.stderr


def test_flag_beats_the_environment(broker: str) -> None:
    """An explicit ``--api-key`` wins, so no existing script changes behaviour."""
    result = _run(broker, "adapters", "list", "--api-key", KEY, "--json", env_key="not-the-key")
    assert result.returncode == 0, result.stderr


def test_an_explicitly_empty_flag_is_not_a_fallback(broker: str) -> None:
    """``--api-key ''`` means "send nothing", not "read the environment".

    A flag the operator typed is never silently overridden by a variable they
    may not know is exported.
    """
    result = _run(broker, "adapters", "list", "--api-key", "", env_key=KEY)
    assert result.returncode == 1, result.stdout
    assert "401" in result.stderr


def test_a_trailing_newline_in_the_environment_is_stripped(broker: str) -> None:
    """``NAUTILUS_API_KEY`` read out of a file carries a newline; the header must not.

    ``require_reviewer`` strips for the same reason; an ``X-API-Key`` with a
    newline on the end matches no configured key and the failure looks like a
    wrong secret.
    """
    result = _run(broker, "adapters", "list", "--json", env_key=f"  {KEY}\n")
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not Path("/proc/self/cmdline").exists(), reason="needs procfs")
def test_the_credential_stays_out_of_argv(broker: str) -> None:
    """The point of the change: nothing readable in ``/proc/<pid>/cmdline``.

    Measured on the CLI's own process rather than asserted about it -- the
    hazard is what another account on the host can read, and ``cmdline`` is
    world-readable while ``environ`` is not.
    """
    env = {k: v for k, v in os.environ.items() if k != "NAUTILUS_API_KEY"}
    env["NAUTILUS_API_KEY"] = KEY
    # A blackhole address, so the process is still alive to be inspected while
    # httpx waits out its connect timeout.
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "nautilus.cli",
            "adapters",
            "list",
            "--url",
            "http://10.255.255.1:1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        cmdline = Path(f"/proc/{proc.pid}/cmdline").read_bytes()
        assert KEY.encode() not in cmdline
        assert oct(Path(f"/proc/{proc.pid}/cmdline").stat().st_mode)[-3:] == "444"
        assert oct(Path(f"/proc/{proc.pid}/environ").stat().st_mode)[-3:] == "400"
    finally:
        proc.kill()
        proc.wait(timeout=15)
