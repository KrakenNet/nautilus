"""WAVE ops12 — the build identifier did not move when the build moved.

Two separate defects, one symptom.

1. **The packaged version rotted for 76 commits.** ``pyproject.toml`` read
   ``0.2.2`` while ``v0.2.3``, ``v0.2.4`` and ``v0.2.5`` were tagged and on
   PyPI. Nothing anywhere went red about it, so an image built from ``HEAD``
   and an image built from ``86232f8`` — differing by the whole of one wave —
   both answered ``GET /healthz`` with ``{"status": "ok", "version": "0.2.2"}``,
   and a wheel built from this tree collided with a released one.

2. **A version is not a build identifier and cannot be made into one.** Every
   commit between two releases legitimately shares a version. Telling two such
   builds apart needs the commit, and the commit is not derivable inside the
   image: ``.dockerignore`` excludes ``.git/``. So it enters as
   ``docker build --build-arg BUILD_REV=...`` and is carried as
   ``NAUTILUS_BUILD_REV``; :mod:`nautilus.build` reads it and ``/healthz``
   publishes it. An image built without the arg reports ``unknown`` — it does
   **not** fall back to the version, because that fallback is what made this
   invisible in the first place.

The rot check below is the part that has to survive. Its rule, and why:

* **A tag pointing at HEAD is the authority when there is one** — you are on a
  release commit, so the packaged version must be that tag.
* **Otherwise the packaged version must be strictly greater than every tag in
  the repository.** Not "equal to the newest tag", and not "greater than the
  newest tag reachable from HEAD": ``v0.2.3``–``v0.2.5`` are *not* ancestors of
  this branch, and a reachability rule would have called ``0.2.2`` correct on
  the exact tree where it was published-and-colliding. The property that
  actually matters is that no artifact built from this tree can claim a string
  a released artifact already claims, and that is a statement about all tags.
* **No ``.git`` — skip.** A wheel or an sdist has no tags to compare against;
  failing there is failing on the absence of evidence, and the release path
  always runs from a checkout.
* **A checkout with no tags — fail, with the fix in the message.** This is the
  hole the check dies in otherwise: ``actions/checkout`` clones at depth 1 and
  fetches no tags by default, so a skip-on-no-tags rule skips in exactly the
  place it is supposed to run. ``.github/workflows/ci.yml`` sets
  ``fetch-tags: true`` for this test, and that one line is what the failure
  message names.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
from packaging.version import InvalidVersion, Version

from nautilus.build import BUILD_REV_ENV, UNKNOWN, build_rev

REPO_ROOT = Path(__file__).resolve().parents[2]
_TAG = re.compile(r"^v(\d+\.\d+\.\d+)$")


def _packaged_version() -> Version:
    raw = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return Version(raw["project"]["version"])


def _git(*args: str) -> str:
    git = shutil.which("git")
    if git is None:  # pragma: no cover — every dev box and CI runner has git
        pytest.skip("git is not on PATH, so there are no tags to compare against")
    result = subprocess.run(  # noqa: S603 — trusted binary discovered via shutil.which
        [git, "-C", str(REPO_ROOT), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.skip(f"git {' '.join(args)} failed here: {result.stderr.strip()}")
    return result.stdout


def _released_versions() -> list[Version]:
    """Every ``vX.Y.Z`` tag in the repository, whether or not HEAD contains it."""
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not a git checkout (installed wheel or sdist): no tags to compare against")
    found: list[Version] = []
    for line in _git("tag", "--list", "v*").splitlines():
        match = _TAG.match(line.strip())
        if match is None:
            continue
        try:
            found.append(Version(match.group(1)))
        except InvalidVersion:  # pragma: no cover — the regex already shapes it
            continue
    assert found, (
        "this is a git checkout with no vX.Y.Z tags, so the packaged version "
        "cannot be checked against what has actually been released. That is a "
        "clone configuration problem, not a reason to pass: `actions/checkout` "
        "fetches no tags at depth 1. Set `fetch-tags: true` on the checkout step "
        "(CI already does), or run `git fetch --tags` locally."
    )
    return sorted(found)


def test_the_packaged_version_has_not_been_overtaken_by_a_release() -> None:
    """RED whenever a tag exists that the packaged version does not lead."""
    released = _released_versions()
    packaged = _packaged_version()

    at_head = sorted(
        Version(m.group(1))
        for line in _git("tag", "--points-at", "HEAD", "--list", "v*").splitlines()
        if (m := _TAG.match(line.strip())) is not None
    )
    if at_head:
        assert packaged == at_head[-1], (
            f"HEAD is tagged v{at_head[-1]} but the tree packages {packaged}; "
            "a release commit and its artifact must carry the same string"
        )
        return

    newest = released[-1]
    assert packaged > newest, (
        f"pyproject.toml packages {packaged}, but v{newest} is already released. "
        f"Every artifact built from this tree calls itself {packaged} — the same "
        "string a published wheel carries — so `pip install` and a local build "
        "produce different software under one name. Bump [project] version past "
        f"{newest} (a `.devN` suffix is the honest choice on an unreleased tree)."
    )


def test_release_please_would_not_propose_an_already_published_version() -> None:
    """The manifest is release-please's record of the last release; it rotted too.

    Left at ``0.2.2`` with ``v0.2.5`` on PyPI, the next release PR proposes
    ``v0.2.3`` — a version the index already holds — and the publish job fails
    on upload rather than on anything a reviewer would see.

    Behind, never level: this asked for ``==`` and so was false on the one
    branch it most needed to be true. A release PR bumps the manifest to the
    version it is proposing while the tag for it does not exist yet — 0.3.0
    recorded against ``v0.2.5`` tagged — which is the release doing its job,
    and ``==`` called it rot and turned #172 red. Only a manifest *below* the
    newest tag causes the collision described above.
    """
    released = _released_versions()
    manifest = json.loads((REPO_ROOT / ".release-please-manifest.json").read_text("utf-8"))
    recorded = Version(manifest["."])
    assert recorded >= released[-1], (
        f".release-please-manifest.json records {recorded} as the last release of "
        f"this package, but v{released[-1]} is tagged. release-please computes the "
        f"next version from that record, so it would propose a version at or below "
        f"v{released[-1]} and the publish would collide."
    )


def test_ci_fetches_the_tags_the_rot_check_needs() -> None:
    """The check above fails loudly with no tags; this keeps that from happening.

    ``actions/checkout`` clones at depth 1 and fetches no tags. Without this the
    version check is red on every CI run for a reason that has nothing to do
    with the version, and the second thing anyone does about that is delete it.
    """
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "fetch-tags: true" in workflow, (
        "ci.yml checks out without fetching tags; "
        "test_the_packaged_version_has_not_been_overtaken_by_a_release cannot run there"
    )


def test_build_rev_reports_unknown_rather_than_guessing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No provenance means no provenance — never a fallback to the version."""
    from nautilus import __version__

    monkeypatch.delenv(BUILD_REV_ENV, raising=False)
    assert build_rev() == UNKNOWN
    assert build_rev() != __version__

    monkeypatch.setenv(BUILD_REV_ENV, "   ")
    assert build_rev() == UNKNOWN, "whitespace is not a build identifier"

    monkeypatch.setenv(BUILD_REV_ENV, " 6b287951 ")
    assert build_rev() == "6b287951"


def test_the_dockerfile_carries_the_build_arg_into_the_runtime_image() -> None:
    """The wiring the network answer depends on, checked without a daemon.

    ``ARG`` in a Dockerfile is scoped to the stage that declares it: an ``ARG``
    before the first ``FROM`` is visible to no stage until re-declared. Deleting
    either half leaves a build that accepts ``--build-arg BUILD_REV`` silently
    and ships an image that answers ``unknown``.
    """
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    stages = text.split("\nFROM ")
    assert text.split("\nFROM ", 1)[0].count('ARG BUILD_REV=""') == 1, (
        "Dockerfile declares no global ARG BUILD_REV before the first FROM"
    )
    runtime = next((s for s in stages if s.startswith("gcr.io/distroless")), None)
    assert runtime is not None, "no distroless runtime stage in the Dockerfile"
    assert "ARG BUILD_REV" in runtime, (
        "the runtime stage does not re-declare ARG BUILD_REV, so the global one "
        "is out of scope there and --build-arg BUILD_REV reaches nothing"
    )
    assert f"ENV {BUILD_REV_ENV}=${{BUILD_REV}}" in runtime, (
        f"the runtime stage does not export {BUILD_REV_ENV}, so nothing in the "
        "running container can read the revision it was built from"
    )


def test_healthz_publishes_a_build_field_distinct_from_the_version(tmp_path: Path) -> None:
    """The network-readable answer, end to end, with no credential."""
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

    previous = os.environ.get(BUILD_REV_ENV)
    os.environ[BUILD_REV_ENV] = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
    try:
        with TestClient(create_app(str(config))) as client:
            body = client.get("/healthz").json()  # note: no X-API-Key
    finally:
        if previous is None:
            del os.environ[BUILD_REV_ENV]
        else:
            os.environ[BUILD_REV_ENV] = previous

    assert body == {
        "status": "ok",
        "version": __version__,
        "build": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
    }
    assert body["build"] != body["version"], (
        "the build field repeats the version, so two images of one release line "
        "answer identically and the field carries nothing"
    )
