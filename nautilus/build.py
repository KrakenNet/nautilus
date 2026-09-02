"""Which build this artifact is, as distinct from which release line it is on.

``nautilus.__version__`` answers *which release line* — it is a property of the
wheel, so every build between two releases shares it. That is not a bug in the
version string, it is what a version string is: 76 consecutive commits of this
tree all installed as ``0.2.2`` and all answered ``/healthz`` with ``0.2.2``,
which is correct and useless for telling two of them apart.

The build revision answers *which commit*, and it cannot be derived from inside
the image: ``.dockerignore`` excludes ``.git/``, so no layer can run
``git describe``. It is handed in at build time
(``docker build --build-arg BUILD_REV=$(git rev-parse HEAD) .``) and carried
into the runtime image as :data:`BUILD_REV_ENV`.

**An image built without it reports** :data:`UNKNOWN` **and never falls back to
the version.** The fallback is precisely what kept the rot invisible: two images
built from different commits both answered with a well-formed version string, so
the answer *looked* healthy while carrying no information. ``unknown`` is not a
build identifier, does not compare equal to one, and makes a rollout that lost
its provenance say so.
"""

from __future__ import annotations

import os

BUILD_REV_ENV = "NAUTILUS_BUILD_REV"
"""Environment variable the image carries the build revision in."""

UNKNOWN = "unknown"
"""What a build with no provenance reports. Deliberately not a version string."""


def build_rev() -> str:
    """Return the revision this artifact was built from, or ``"unknown"``.

    Read per call rather than at import so a process can be started with a
    revision its parent knows and the module can be imported by a test that
    controls the environment.
    """
    return os.environ.get(BUILD_REV_ENV, "").strip() or UNKNOWN


__all__ = ["BUILD_REV_ENV", "UNKNOWN", "build_rev"]
