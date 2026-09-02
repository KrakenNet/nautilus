"""Which build this artifact is, as distinct from which release line it is on.

``nautilus.__version__`` answers *which release line* — it is a property of the
wheel, so every build between two releases shares it. That is not a bug in the
version string, it is what a version string is: 76 consecutive commits of this
tree all installed as ``0.2.2`` and all answered ``/healthz`` with ``0.2.2``,
which is correct and useless for telling two of them apart.

The build revision answers *which commit*, and it cannot be derived from inside
the image: ``.dockerignore`` excludes ``.git/``, so no layer can run
``git describe``. It is handed in at build time
(``docker build --build-arg BUILD_REV=$(git rev-parse HEAD) .``).

**Where the answer comes from, in order.**

1. :data:`STAMP_PATH` — a file the image build writes next to this module. It is
   part of the artifact, so it answers the same on every process started from
   that artifact and nothing at ``docker run`` time can change it. This is the
   whole point: a build identifier that the command line can set identifies the
   command line. Two invented 40-hex strings handed to ``docker run -e`` were
   once enough to make two containers of *one image* claim to be different
   builds, and to make a container claim a commit its image was not built from.
2. :data:`BUILD_REV_ENV` — consulted **only when there is no stamp**. A source
   checkout, a ``pip install`` and a unit file whose parent knows the revision
   all carry no stamp, and refusing the variable there would leave every
   non-image deployment permanently :data:`UNKNOWN`.
3. :data:`UNKNOWN` otherwise.

**An artifact with no provenance reports** :data:`UNKNOWN` **and never falls
back to the version.** The fallback is precisely what kept the rot invisible:
two images built from different commits both answered with a well-formed version
string, so the answer *looked* healthy while carrying no information. ``unknown``
is not a build identifier, does not compare equal to one, and makes a rollout
that lost its provenance say so. An image built without ``--build-arg BUILD_REV``
carries an *empty* stamp, which is provenance saying "none" — it answers
``unknown`` and cannot be talked out of it either.

**A disagreement is reported, not resolved in silence.** When the environment
names a revision the stamp does not, :func:`build_rev_override` returns the value
that was ignored, ``GET /healthz`` publishes it as ``build_override_ignored`` and
``nautilus version`` warns on stderr. Serving the stamp and saying nothing would
be indistinguishable, to the operator who set the variable, from serving the
override.
"""

from __future__ import annotations

import os
from pathlib import Path

BUILD_REV_ENV = "NAUTILUS_BUILD_REV"
"""Environment variable a revision may be handed in through, absent a stamp."""

STAMP_PATH = Path(__file__).with_name("_build_rev")
"""File the image build stamps this artifact's revision into.

Beside this module rather than at a fixed absolute path, so it travels with the
copy of the package the interpreter actually imported: the runtime image sets
``PYTHONPATH=/app`` and the answer has to come from ``/app/nautilus``, not from
whatever a second install left elsewhere on ``sys.path``.
"""

UNKNOWN = "unknown"
"""What a build with no provenance reports. Deliberately not a version string."""


def _stamped() -> str | None:
    """The artifact's own revision, ``""`` if it declares none, ``None`` if unstamped.

    The three states are distinct and the middle one carries the weight: an
    image built without ``--build-arg BUILD_REV`` has *declared* that it has no
    revision, which is not the same as a wheel that was never in a position to
    declare anything.

    A stamp that is *present and unreadable* is the second state, not the
    third. Reading every ``OSError`` as "unstamped" let a mode-000 or
    otherwise-unopenable stamp fall through to :data:`BUILD_REV_ENV`, which
    anyone who can set this process's environment controls -- so damaging the
    file was enough to choose what the artifact claims it was built from. An
    artifact that carries a stamp answers from the stamp or answers
    ``unknown``; it never answers from the environment.
    """
    try:
        return STAMP_PATH.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError:
        return ""


def build_rev() -> str:
    """Return the revision this artifact was built from, or ``"unknown"``.

    Read per call rather than at import so a process can be started with a
    revision its parent knows and the module can be imported by a test that
    controls the environment.
    """
    stamped = _stamped()
    if stamped is not None:
        return stamped or UNKNOWN
    return os.environ.get(BUILD_REV_ENV, "").strip() or UNKNOWN


def build_rev_override() -> str | None:
    """The :data:`BUILD_REV_ENV` value this artifact's stamp overrode, if any.

    ``None`` when there is nothing to disagree about: no stamp, no variable, or
    a variable that repeats what the stamp already says — which is the ordinary
    case, since the image exports the same build arg it stamps.
    """
    stamped = _stamped()
    if stamped is None:
        return None
    supplied = os.environ.get(BUILD_REV_ENV, "").strip()
    return supplied if supplied and supplied != (stamped or UNKNOWN) else None


__all__ = ["BUILD_REV_ENV", "STAMP_PATH", "UNKNOWN", "build_rev", "build_rev_override"]
