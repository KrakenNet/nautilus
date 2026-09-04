"""WAVE ops13 — the reload existed and no documented path reached it.

WAVE ops12 shipped ``SIGHUP`` config reload. An operator configuring only from
``docs/`` could not use it, for one reason: the command the deployment guide
(``docs/how-to/deploying.md``) gave for sending the signal on Kubernetes was

.. code-block:: text

    kubectl -n nautilus exec deployment/nautilus -- pkill -HUP -f 'nautilus serve'

and the runtime image is ``gcr.io/distroless/cc-debian13``. There is no
``pkill`` in it — there is nothing in ``/bin``, ``/usr/bin``, ``/sbin`` or
``/usr/sbin`` at all. The whole of the image's ``$PATH`` is eighteen files, and
seventeen of them are the virtualenv's console scripts. Against a real cluster
that line is::

    error: Internal error occurred: ... OCI runtime exec failed: exec failed:
    unable to start container process: exec: "pkill": executable file not found in $PATH

``docker kill -s HUP`` covers the container-runtime path because it runs on the
host, so the defect was invisible from the docker side of the page. On
Kubernetes there is no host to run it from, and the feature was unreachable.

The two tests below are the mechanical check WAVE ops12 said it did not have.
Its own commit message: "Not covered by anything mechanical: citation_lock.py
scans docs/**.md only, so deploy/README.md's new 357 lines are held by this
wave's verification alone."

**What separates a procedure from a transcript.** A ``bash`` block is an
instruction — every command in it has to run. A ``console`` block is a pasted
recording, and §11 of the deployment guide deliberately records ``sh``, ``ls``,
``curl`` and ``pip`` *failing*, because enumerating what is absent is the point
of that section. So the check reads ``bash`` blocks and leaves ``console``
blocks alone.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
_GUIDE = REPO_ROOT / "docs" / "how-to" / "deploying.md"
_IMAGE_TAG = "nautilus:test"  # same tag and argv as tests/integration/test_docker_image.py
_DOCKER = shutil.which("docker")

# ``kubectl [flags] exec [flags] <target> [flags] -- argv...`` and
# ``docker exec [flags] <container> argv...``. Both capture the first word of
# argv, which is the executable the container runtime has to resolve on $PATH.
_KUBECTL_EXEC = re.compile(r"\bkubectl\b[^|;&]*?\bexec\b[^|;&]*?--\s+(\S+)")
_DOCKER_EXEC = re.compile(r"\bdocker\s+exec\s+(?:-\S+\s+)*\S+\s+(\S+)")


def _docker_available() -> bool:
    """True when a Docker daemon answers."""
    if _DOCKER is None:
        return False
    try:
        probe = subprocess.run(  # noqa: S603 - trusted binary from shutil.which
            [_DOCKER, "info", "--format", "{{.ServerVersion}}"],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0 and bool(probe.stdout.strip())


@pytest.fixture(scope="session")
def image_executables() -> frozenset[str]:
    """Every name the image can exec, as the container runtime would resolve it.

    Returned as bare names *and* absolute paths, because the documentation uses
    both forms: ``python`` relies on the image's ``PATH``, while
    ``/app/.venv/bin/python`` names the file.
    """
    if not _docker_available():
        pytest.skip("docker daemon not available")
    build = subprocess.run(  # noqa: S603 - trusted binary from shutil.which
        [_DOCKER or "docker", "build", "--target", "runtime", "-t", _IMAGE_TAG, "."],
        check=False,
        capture_output=True,
        cwd=str(REPO_ROOT),
        timeout=900,
    )
    if build.returncode != 0:
        pytest.fail(f"docker build failed:\n{build.stderr.decode('utf-8', errors='replace')}")
    listing = subprocess.run(  # noqa: S603 - trusted binary from shutil.which
        [
            _DOCKER or "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/app/.venv/bin/python",
            _IMAGE_TAG,
            "-c",
            (
                "import os\n"
                "for d in os.environ['PATH'].split(':'):\n"
                "    try: names = os.listdir(d)\n"
                "    except OSError: continue\n"
                "    for n in names:\n"
                "        p = os.path.join(d, n)\n"
                "        if os.access(p, os.X_OK):\n"
                "            print(n); print(p)\n"
            ),
        ],
        check=False,
        capture_output=True,
        timeout=120,
    )
    assert listing.returncode == 0, listing.stderr.decode("utf-8", errors="replace")
    found = frozenset(listing.stdout.decode().split())
    assert "python" in found, f"the image lost its interpreter: {sorted(found)}"
    return found


def _bash_blocks(text: str) -> Iterator[str]:
    """Yield the body of every fenced block whose language is ``bash``."""
    for match in re.finditer(r"^```(\w*)\n(.*?)^```", text, re.MULTILINE | re.DOTALL):
        if match.group(1) == "bash":
            yield match.group(2)


def _documented_pages() -> list[Path]:
    """Every operator-facing markdown page that can name a container command."""
    return sorted((REPO_ROOT / "docs").rglob("*.md"))


def _in_container_commands() -> list[tuple[Path, str]]:
    """(page, executable) for every command a procedure runs inside the image."""
    out: list[tuple[Path, str]] = []
    for page in _documented_pages():
        for block in _bash_blocks(page.read_text(encoding="utf-8")):
            # Fold shell line continuations first, or the executable of a
            # command wrapped after `--` is read as a backslash.
            for line in block.replace("\\\n", " ").splitlines():
                for pattern in (_KUBECTL_EXEC, _DOCKER_EXEC):
                    hit = pattern.search(line)
                    # A `$VAR` or `"$(...)"` executable is not resolvable here;
                    # nothing in this documentation set uses one, and inventing
                    # a rule for it would be a rule with no subject.
                    if hit and not hit.group(1).startswith(("$", '"', "-")):
                        out.append((page, hit.group(1)))
    return out


@pytest.mark.docker
def test_every_documented_in_container_command_exists_in_the_image(
    image_executables: frozenset[str],
) -> None:
    """A procedure block may only name an executable the image actually has.

    This is the check that was missing. ``pkill`` sat in the deployment guide
    for a whole wave as the one documented way to reach the reload on
    Kubernetes, and nothing anywhere went red.
    """
    commands = _in_container_commands()
    assert commands, (
        "found no `kubectl exec`/`docker exec` procedure in docs/**.md — the "
        "parser stopped matching, so this check is vacuous"
    )
    missing = [
        (page.relative_to(REPO_ROOT).as_posix(), exe)
        for page, exe in commands
        if exe not in image_executables
    ]
    assert not missing, (
        "the documentation tells an operator to run these inside the distroless "
        f"runtime image, which has no such executable: {missing}. The image's "
        "$PATH holds the virtualenv's console scripts and nothing else; reach "
        "for /app/.venv/bin/python instead."
    )


def test_the_reload_procedure_names_a_signal_sender_that_ships() -> None:
    """The deployment guide must give a Kubernetes operator a way to signal.

    Text-only, so it holds on a machine with no Docker: the reload section has
    to send ``SIGHUP`` through the interpreter, because that is the only
    executable in the image that can send a signal at all.
    """
    guide = _GUIDE.read_text(encoding="utf-8")
    # Fold continuations: the command is wrapped across two lines on the page.
    folded = guide.replace("\\\n", " ")
    signallers = [
        line
        for line in folded.splitlines()
        if "kubectl" in line and "exec" in line and "signal.SIGHUP" in line
    ]
    assert signallers, (
        "docs/how-to/deploying.md gives a Kubernetes operator no way to send SIGHUP. "
        "`docker kill -s HUP` runs on the host and has no cluster equivalent, and "
        "the image has no pkill, no kill and no shell — so without a "
        "`kubectl exec … -- /app/.venv/bin/python -c 'os.kill(1, signal.SIGHUP)'` "
        "the reload that ships is unreachable from a cluster."
    )


def test_the_container_runtime_path_mounts_the_config_directory() -> None:
    """A file bind mount carries a rewrite; it does not carry a replacement.

    ``-v host/nautilus.yaml:/config/nautilus.yaml:ro`` binds an *inode*. An
    editor, ``sed -i``, or any writer that renames a temp file into place
    leaves the container reading the old inode forever, and ``SIGHUP`` then
    re-reads bytes that have not changed. Mounting the directory — which is
    what the ConfigMap volume in ``deployment.yaml`` does — carries both.
    """
    guide = _GUIDE.read_text(encoding="utf-8")
    assert "-v /srv/nautilus/config/nautilus.yaml:/config/nautilus.yaml:ro" not in guide, (
        "docs/how-to/deploying.md bind-mounts the config file; a rename on the host "
        "never reaches the container through it"
    )
    assert "-v /srv/nautilus/config:/config:ro" in guide, (
        "docs/how-to/deploying.md should mount the config directory, matching the "
        "ConfigMap volume in deployment.yaml"
    )
