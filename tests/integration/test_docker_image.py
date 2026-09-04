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


# ---------------------------------------------------------------------------
# WAVE E4 — the image was inspected but never started.
# ---------------------------------------------------------------------------


def test_the_runtime_image_can_actually_start(built_image: str) -> None:
    """The distroless image must run, not merely build and inspect well.

    Reproduced first-hand before the fix::

        docker run --rm nautilus:test version
        exec: "/app/.venv/bin/python": stat /app/.venv/bin/python:
        no such file or directory

    ``/app/.venv/bin/python`` is a symlink into ``/usr/local/bin`` on the
    builder, and the runtime stage copied only ``/app``. Every assertion above
    reads ``docker image inspect``, so an image that could not execute a single
    byte passed all three.
    """
    result = subprocess.run(  # noqa: S603 — trusted binary
        [_DOCKER or "docker", "run", "--rm", built_image, "version"],
        check=False,
        capture_output=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"the runtime image could not run `nautilus version` "
        f"(exit {result.returncode}):\n"
        f"{result.stderr.decode('utf-8', errors='replace')}"
    )


def test_the_default_build_target_is_the_distroless_runtime() -> None:
    """``docker build .`` must produce the image the Dockerfile says it does.

    The Dockerfile's own header reads "Default target is `runtime`", and the
    debug stage is documented as opt-in and "NOT built by CI". It was declared
    last, so it won the default-last-stage selection: ``docker build -t
    nautilus:latest .`` produced a python:3.14-slim image with bash and apt.
    AC-16.5 held only for the ``--target runtime`` this suite passes and the
    docs never mention.
    """
    root = _repo_root()
    tag = "nautilus:test-default-target"
    build = subprocess.run(  # noqa: S603 — trusted binary
        [_DOCKER or "docker", "build", "-t", tag, "."],
        check=False,
        capture_output=True,
        cwd=str(root),
        timeout=900,
    )
    assert build.returncode == 0, (
        f"default-target docker build failed:\n{build.stderr.decode('utf-8', errors='replace')}"
    )
    shell = subprocess.run(  # noqa: S603 — trusted binary
        [_DOCKER or "docker", "run", "--rm", "--entrypoint", "sh", tag, "-c", "echo hi"],
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert shell.returncode != 0, (
        "`docker build .` with no --target produced an image WITH a shell. "
        "The debug stage is declared last and wins the default, so the "
        "documented build command ships the operator-only image."
    )


# ---------------------------------------------------------------------------
# WAVE ops12 — the identifier the image reports has to move with the image.
# ---------------------------------------------------------------------------


def _run_version(image: str, *, env: str | None = None) -> tuple[int, list[str], str]:
    """``docker run --rm [-e env] <image> version`` → ``(code, stdout lines, stderr)``."""
    opts = ["-e", env] if env is not None else []
    result = subprocess.run(  # noqa: S603 — trusted binary
        [_DOCKER or "docker", "run", "--rm", *opts, image, "version"],
        check=False,
        capture_output=True,
        timeout=120,
    )
    return (
        result.returncode,
        result.stdout.decode("utf-8", errors="replace").splitlines(),
        result.stderr.decode("utf-8", errors="replace"),
    )


def test_version_subcommand_reports_the_packaged_version_and_an_honest_build(
    built_image: str,
) -> None:
    """The only way to ask a distroless image what it is without starting it.

    The fixture builds with no ``--build-arg BUILD_REV``, which is the case that
    has to be got right: the image says ``unknown``. It does **not** repeat the
    version — that fallback is what let 76 commits of images all answer with one
    well-formed string and look healthy doing it.
    """
    import tomllib

    packaged = tomllib.loads((_repo_root() / "pyproject.toml").read_text(encoding="utf-8"))
    code, lines, _ = _run_version(built_image)
    assert code == 0, f"`docker run --rm {built_image} version` exited {code}"
    assert lines[0] == packaged["project"]["version"], (
        f"line 1 must be the packaged version alone; got {lines[0]!r}"
    )
    assert lines[1] == "build: unknown", (
        "an image built without --build-arg BUILD_REV must say so, not fall "
        f"back to the version; got {lines[1]!r}"
    )


def test_the_build_arg_is_what_two_images_of_one_release_line_differ_by() -> None:
    """Two builds of the same source, two revisions, two answers.

    Everything above the stamp is byte-identical between these two builds, so
    this is also the check that the ``ARG``/``ENV`` pair sits late enough to be
    cheap: the second build re-uses every layer.
    """
    root = _repo_root()
    # Two arbitrary distinct 40-hex values: this asserts the *wiring* — that
    # what --build-arg receives is what the container reports — so what matters
    # is that they differ, not that they name commits. Real shas would need
    # HEAD~1, which does not exist in CI's depth-1 clone.
    tags = {
        "nautilus:test-rev-a": "1111111111111111111111111111111111111111",
        "nautilus:test-rev-b": "2222222222222222222222222222222222222222",
    }
    answers: dict[str, str] = {}
    try:
        for tag, rev in tags.items():
            build = subprocess.run(  # noqa: S603 — trusted binary
                [
                    _DOCKER or "docker",
                    "build",
                    "--target",
                    "runtime",
                    "--build-arg",
                    f"BUILD_REV={rev}",
                    "-t",
                    tag,
                    ".",
                ],
                check=False,
                capture_output=True,
                cwd=str(root),
                timeout=900,
            )
            assert build.returncode == 0, (
                f"build of {tag} failed:\n{build.stderr.decode('utf-8', errors='replace')}"
            )
            code, lines, _ = _run_version(tag)
            assert code == 0, f"`docker run --rm {tag} version` exited {code}"
            answers[tag] = lines[1]
            assert answers[tag] == f"build: {rev}", (
                f"{tag} was built with BUILD_REV={rev} and reports {answers[tag]!r}; "
                "the --build-arg does not reach the runtime image"
            )
        a, b = answers.values()
        assert a != b, "two images built from different revisions report the same build"
    finally:
        subprocess.run(  # noqa: S603 — trusted binary
            [_DOCKER or "docker", "image", "rm", "-f", *tags],
            check=False,
            capture_output=True,
            timeout=120,
        )


# ---------------------------------------------------------------------------
# WAVE ops14 — the identifier was a property of argv, not of the image.
# ---------------------------------------------------------------------------


_SPOOF = "4d5a1c9e83b27f60a1d4c8e2b95f307a6c1e8b42"


def test_the_command_line_cannot_tell_an_image_which_build_it_is(built_image: str) -> None:
    """``docker run -e NAUTILUS_BUILD_REV=…`` must not change the answer.

    The session fixture builds with no ``--build-arg BUILD_REV``, which is
    exactly the case that was passing dishonestly: two such images and two
    invented 40-hex strings handed to ``docker run -e`` were enough to satisfy a
    build-identity check neither image could satisfy on its own. The image now
    carries its own answer and says when it was asked to say something else.
    """
    code, lines, err = _run_version(built_image, env=f"NAUTILUS_BUILD_REV={_SPOOF}")
    assert code == 0, f"`docker run --rm -e … {built_image} version` exited {code}: {err}"
    assert lines[1] == "build: unknown", (
        "an image that was built with no revision accepted one from its command "
        f"line; got {lines[1]!r}"
    )
    assert _SPOOF in err and "ignored" in err, (
        "the override was discarded in silence, which is indistinguishable from "
        f"an image that never saw it; stderr was {err!r}"
    )


def test_a_stamped_image_reports_its_own_revision_over_an_override() -> None:
    """The stamp beats the environment on a real image, not only in-process.

    Also the check that the stamp is reachable at runtime at all: it is copied
    onto ``/app/nautilus``, and if ``PYTHONPATH`` or the venv layout ever moved
    the imported copy of the package elsewhere, the file would still be in the
    image and read by nothing.
    """
    root = _repo_root()
    rev = "3333333333333333333333333333333333333333"
    tag = "nautilus:test-rev-stamped"
    try:
        build = subprocess.run(  # noqa: S603 — trusted binary
            [
                _DOCKER or "docker",
                "build",
                "--target",
                "runtime",
                "--build-arg",
                f"BUILD_REV={rev}",
                "-t",
                tag,
                ".",
            ],
            check=False,
            capture_output=True,
            cwd=str(root),
            timeout=900,
        )
        assert build.returncode == 0, (
            f"build of {tag} failed:\n{build.stderr.decode('utf-8', errors='replace')}"
        )

        code, lines, err = _run_version(tag, env=f"NAUTILUS_BUILD_REV={_SPOOF}")
        assert code == 0, f"`docker run --rm -e … {tag} version` exited {code}: {err}"
        assert lines[1] == f"build: {rev}", (
            f"{tag} was stamped {rev} and reported {lines[1]!r} under an override"
        )
        assert _SPOOF in err, f"the ignored override was not reported; stderr was {err!r}"

        # Same value where a release check can read it without entering the container.
        label = _inspect(tag, '{{index .Config.Labels "org.opencontainers.image.revision"}}')
        assert label == rev, (
            "org.opencontainers.image.revision does not match what the container "
            f"answers ({label!r} vs {rev!r}), so the label cannot corroborate it"
        )
    finally:
        subprocess.run(  # noqa: S603 — trusted binary
            [_DOCKER or "docker", "image", "rm", "-f", tag],
            check=False,
            capture_output=True,
            timeout=120,
        )
