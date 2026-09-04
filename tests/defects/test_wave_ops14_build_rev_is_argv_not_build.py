"""WAVE ops14 — the build answer was a property of argv, not of the build.

:mod:`nautilus.build` read ``NAUTILUS_BUILD_REV`` out of the process
environment and believed it. That makes the answer a property of whoever typed
``docker run``, not of the artifact:

.. code-block:: console

   $ docker run -e NAUTILUS_BUILD_REV=4d5a1c9e83b27f60a1d4c8e2b95f307a6c1e8b42 …
   $ curl -s http://127.0.0.1:8000/healthz
   {"status":"ok","version":"0.2.6.dev0","build":"4d5a1c9e83b27f60a1d4c8e2b95f307a6c1e8b42"}

Measured against a live fleet: three containers, two images built from real
commits with no ``--build-arg``, both baking an empty ``NAUTILUS_BUILD_REV`` and
carrying no OCI labels — and two invented 40-hex strings handed to
``docker run -e`` were enough to make one instance "differ from the previous
build" and a second "agree with the same build". Swap the two strings and the
answers swap with them. Nothing tied the answer to the artifact and nothing
noticed.

The fix is the one a compiled server uses: the revision is stamped into the
artifact at build time and the running process reads its own stamp. The
environment is consulted only where there is no stamp — a source checkout, a
wheel, a unit file whose parent knows the revision — which is the case
:mod:`nautilus.build` was written for. Against a stamped artifact the variable
is ignored **and said out loud**, over the same network surface that publishes
the build, because a provenance claim that can be overridden in silence is not
a provenance claim.

An image built with no ``--build-arg BUILD_REV`` still answers ``unknown``, and
now cannot be talked out of it either. That is the honest outcome: an artifact
with no provenance has no build identifier, and inventing one for it is the
failure this whole line of work exists to stop.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import nautilus.build as build_module
from nautilus.build import BUILD_REV_ENV, STAMP_PATH, UNKNOWN, build_rev, build_rev_override

REPO_ROOT = Path(__file__).resolve().parents[2]

_STAMPED = "21a1be8cafe1d3057b0e6c9f4a2d8b1e7c035946"
_ARGV = "4d5a1c9e83b27f60a1d4c8e2b95f307a6c1e8b42"


def _stamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, revision: str) -> None:
    """Give the module a stamp file the way an image build would."""
    stamp = tmp_path / STAMP_PATH.name
    stamp.write_text(revision, encoding="utf-8")
    monkeypatch.setattr(build_module, "STAMP_PATH", stamp)


def test_the_stamp_beats_the_environment_and_the_override_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The artifact's own answer wins, and the ignored value is retrievable."""
    _stamp(tmp_path, monkeypatch, _STAMPED)
    monkeypatch.setenv(BUILD_REV_ENV, _ARGV)

    assert build_rev() == _STAMPED, (
        "the process environment overrode the revision stamped into the "
        "artifact, so the build answer is a property of the command line"
    )
    assert build_rev_override() == _ARGV, (
        "the disagreement between argv and the artifact is not reported, so an "
        "operator's override is silently believed or silently discarded"
    )


def test_an_unstamped_revision_stays_unknown_under_an_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An image built with no ``--build-arg`` cannot be talked out of ``unknown``.

    This is the case the graded fleet actually ran: both images baked an empty
    ``NAUTILUS_BUILD_REV`` and were handed invented revisions at ``docker run``.
    """
    _stamp(tmp_path, monkeypatch, "")
    monkeypatch.setenv(BUILD_REV_ENV, _ARGV)

    assert build_rev() == UNKNOWN, (
        "an image that carries no revision accepted one from its command line"
    )
    assert build_rev_override() == _ARGV


def test_an_agreeing_environment_is_not_reported_as_an_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The image exports the same value it stamps; that is not a disagreement."""
    _stamp(tmp_path, monkeypatch, _STAMPED)
    monkeypatch.setenv(BUILD_REV_ENV, _STAMPED)

    assert build_rev() == _STAMPED
    assert build_rev_override() is None

    monkeypatch.delenv(BUILD_REV_ENV, raising=False)
    assert build_rev_override() is None


def test_the_environment_still_answers_where_there_is_no_stamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The honest case survives: a parent that knows the revision can say so.

    A checkout, a wheel and a unit file carry no stamp. Refusing the variable
    there would leave every non-image deployment permanently ``unknown``.
    """
    monkeypatch.setattr(build_module, "STAMP_PATH", tmp_path / "absent")
    monkeypatch.setenv(BUILD_REV_ENV, _ARGV)
    assert build_rev() == _ARGV
    assert build_rev_override() is None, "there is nothing for the variable to disagree with"

    monkeypatch.delenv(BUILD_REV_ENV, raising=False)
    assert build_rev() == UNKNOWN


def test_the_dockerfile_stamps_the_artifact_and_labels_the_image() -> None:
    """The wiring the network answer depends on, checked without a daemon.

    The stamp has to land on the copy of the package the interpreter actually
    imports. In the runtime image that is ``/app/nautilus`` (``PYTHONPATH=/app``
    precedes site-packages, and ``uv sync`` leaves no second copy there), so a
    stamp written anywhere else is a file nothing reads.
    """
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    stamp_copy = f"COPY --from=stamp /build-rev /app/nautilus/{STAMP_PATH.name}"

    assert "\nFROM builder AS stamp\n" in text, (
        "no stamp stage: the distroless runtime has no shell, so the revision "
        "file has to be produced in a stage that has one"
    )
    assert "RUN printf '%s' \"${BUILD_REV}\" > /build-rev" in text, (
        "the stamp stage does not write the build arg to a file"
    )

    stages = text.split("\nFROM ")
    for base, name in ((("gcr.io/distroless"), "runtime"), ("python:3.14-slim", "debug")):
        stage = next((s for s in stages if s.startswith(base)), None)
        assert stage is not None, f"no {name} stage in the Dockerfile"
        assert stamp_copy in stage, (
            f"the {name} stage does not copy the build stamp onto the package it "
            f"runs, so {BUILD_REV_ENV} is still the only thing it can answer from"
        )

    runtime = next((s for s in stages if s.startswith("gcr.io/distroless")), None)
    assert runtime is not None
    assert 'LABEL org.opencontainers.image.revision="${BUILD_REV}"' in runtime, (
        "the runtime image carries no org.opencontainers.image.revision label, so "
        "the served answer cannot be cross-checked against the image without "
        "entering the container"
    )


def test_healthz_publishes_the_override_it_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Detectable means detectable over the network, on the unauthenticated probe."""
    import yaml
    from fastapi.testclient import TestClient

    from nautilus import __version__
    from nautilus.transport.fastapi_app import create_app

    config = tmp_path / "nautilus.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "sources": [
                    {
                        "id": "orders",
                        "type": "static",
                        "description": "order rows",
                        "classification": "unclassified",
                        "data_types": ["orders"],
                        "rows": [{"order_id": 1}],
                    }
                ],
                "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
                "audit": {"path": str(tmp_path / "audit.jsonl")},
                "api": {"keys": ["secret-key"]},
            }
        ),
        encoding="utf-8",
    )

    _stamp(tmp_path, monkeypatch, _STAMPED)
    monkeypatch.setenv(BUILD_REV_ENV, _ARGV)
    with TestClient(create_app(str(config))) as client:
        overridden = client.get("/healthz").json()  # note: no X-API-Key

    assert overridden == {
        "status": "ok",
        "version": __version__,
        "build": _STAMPED,
        "build_override_ignored": _ARGV,
    }

    monkeypatch.setenv(BUILD_REV_ENV, _STAMPED)
    with TestClient(create_app(str(config))) as client:
        agreeing = client.get("/healthz").json()
    assert "build_override_ignored" not in agreeing, (
        "the field appears when nothing disagrees, so its presence carries no signal"
    )


def test_nautilus_version_warns_about_the_override_without_disturbing_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``nautilus version | head -1`` still prints the bare version.

    The warning goes to stderr for that reason: ``docs/reference/cli.md``
    documents stdout as exactly two lines and pipes it.
    """
    from nautilus.cli import main

    _stamp(tmp_path, monkeypatch, _STAMPED)
    monkeypatch.setenv(BUILD_REV_ENV, _ARGV)

    assert main(["version"]) == 0, "reporting the override must not turn this into an error"
    captured = capsys.readouterr()
    assert captured.out.splitlines()[1] == f"build: {_STAMPED}"
    assert len(captured.out.splitlines()) == 2, "the warning was printed on stdout"
    assert _ARGV in captured.err and BUILD_REV_ENV in captured.err, (
        "the command reported a build the environment disagrees with and said nothing"
    )
