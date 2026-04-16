"""Docker smoke test — size, no-shell, HEALTHCHECK (Task 4.6).

Asserts the distroless runtime image produced by the repo ``Dockerfile`` meets
the Phase-2 release constraints:

* **Size ≤ 200 MB** (NFR-10): total image size reported by
  ``docker image inspect`` is under the budget.
* **No shell in the image** (AC-16.5 / FR-31): invoking ``docker run
  --entrypoint sh nautilus:test`` must fail because the distroless base has
  no ``/bin/sh``.
* **HEALTHCHECK invokes ``nautilus health``** (FR-32 / AC-16.2 / AC-16.4):
  the directive parsed from ``docker image inspect`` mentions both
  ``nautilus`` and ``health``.

The test is skipped cleanly when the local Docker daemon is unreachable so
developer workstations without Docker can still run the full integration
suite. On CI (and any host with Docker), the build runs once per session
and the three assertions are independent.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

pytestmark = [pytest.mark.docker, pytest.mark.integration]


_DOCKER = shutil.which("docker")
if _DOCKER is None:
    pytest.skip("docker daemon not available", allow_module_level=True)


def _docker_daemon_live() -> bool:
    """Return True when the Docker daemon responds to ``docker info``."""
    try:
        result = subprocess.run(  # noqa: S603 — trusted binary discovered via shutil.which
            [_DOCKER or "docker", "info", "--format", "{{.ServerVersion}}"],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        return False
    except OSError:
        return False
    return result.returncode == 0 and bool(result.stdout.strip())


if not _docker_daemon_live():
    pytest.skip("docker daemon not available", allow_module_level=True)


_IMAGE_TAG = "nautilus:test"
_SIZE_BUDGET_BYTES = 200 * 1024 * 1024  # NFR-10: 200 MB ceiling.


def _repo_root() -> Path:
    """Locate the repo root (dir containing ``Dockerfile``)."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "Dockerfile").is_file():
            return parent
    pytest.fail("Dockerfile not found walking up from test file")


@pytest.fixture(scope="session")
def built_image() -> str:
    """Build ``nautilus:test`` once per session; return the tag."""
    root = _repo_root()
    # `--target runtime` pins the distroless stage — the Dockerfile ships a
    # later `debug` stage (opt-in operator target, UQ-5 / D-17) that would
    # otherwise win the default-last-stage selection.
    build = subprocess.run(  # noqa: S603 — trusted binary discovered via shutil.which
        [
            _DOCKER or "docker",
            "build",
            "--target",
            "runtime",
            "-t",
            _IMAGE_TAG,
            ".",
        ],
        check=False,
        capture_output=True,
        cwd=str(root),
        timeout=900,
    )
    if build.returncode != 0:
        pytest.fail(
            "docker build failed:\n"
            f"stdout:\n{build.stdout.decode('utf-8', errors='replace')}\n"
            f"stderr:\n{build.stderr.decode('utf-8', errors='replace')}"
        )
    return _IMAGE_TAG


def _inspect(image: str, fmt: str) -> str:
    """Run ``docker image inspect`` with a Go template and return stdout."""
    result = subprocess.run(  # noqa: S603 — trusted binary
        [_DOCKER or "docker", "image", "inspect", image, "--format", fmt],
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"docker image inspect failed: {result.stderr.decode('utf-8', errors='replace')}"
    )
    return result.stdout.decode("utf-8", errors="replace").strip()


def test_image_size_under_budget(built_image: str) -> None:
    """NFR-10: distroless runtime image stays ≤ 200 MB."""
    raw = _inspect(built_image, "{{.Size}}")
    size_bytes = int(raw)
    assert size_bytes <= _SIZE_BUDGET_BYTES, (
        f"image {built_image} is {size_bytes / (1024 * 1024):.1f} MB, "
        f"exceeds NFR-10 budget of {_SIZE_BUDGET_BYTES // (1024 * 1024)} MB"
    )


def test_image_has_no_shell(built_image: str) -> None:
    """AC-16.5 / FR-31: ``sh`` entrypoint must fail on a distroless image."""
    result = subprocess.run(  # noqa: S603 — trusted binary
        [
            _DOCKER or "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            built_image,
            "-c",
            "echo hi",
        ],
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode != 0, (
        "docker run --entrypoint sh unexpectedly succeeded — image is NOT "
        "distroless (shell present). stdout="
        f"{result.stdout.decode('utf-8', errors='replace')!r}"
    )


def test_healthcheck_invokes_nautilus_health(built_image: str) -> None:
    """FR-32 / AC-16.2 / AC-16.4: HEALTHCHECK calls ``nautilus health``."""
    raw = _inspect(built_image, "{{json .Config.Healthcheck}}")
    assert raw and raw != "null", f"image {built_image} has no HEALTHCHECK directive (got: {raw!r})"
    healthcheck = cast("dict[str, Any]", json.loads(raw))
    raw_test = healthcheck.get("Test")
    assert isinstance(raw_test, list) and raw_test, (
        f"HEALTHCHECK.Test is not a non-empty list: {raw_test!r}"
    )
    test_cmd: list[str] = [str(part) for part in cast("list[Any]", raw_test)]
    # First element is one of CMD / CMD-SHELL / NONE.
    kind = test_cmd[0]
    assert kind == "CMD", (
        f"HEALTHCHECK must use exec form CMD (distroless has no shell); got {kind!r}"
    )
    joined = " ".join(test_cmd[1:])
    assert "nautilus" in joined and "health" in joined, (
        f"HEALTHCHECK does not invoke 'nautilus health'; got args={test_cmd[1:]!r}"
    )
