"""Where a missing optional dependency sends the operator.

Nautilus runs in two shapes and they take opposite remedies. A host install
(``pip`` / ``uv``) can add an extra to an environment that already exists. The
published container image cannot: its runtime stage is
``gcr.io/distroless/cc-debian13`` — no shell, no package manager, no ``pip`` —
so the only way to get a driver into it is to build a new image with
``--build-arg EXTRAS``. A message naming only the first remedy is unusable in
the deployment `docs/how-to/deploying.md` walks the reader through, which is
why every "you are missing X" message in this package renders both.

The default image installs ``--extra otel`` and nothing else. That is stated in
the extras table in `docs/how-to/deploying.md` §1, and
``tests/defects/test_wave_ops14_image_extras.py`` holds the table against the
``Dockerfile`` and against the distributions a built image actually carries,
rather than trusting the sentence to stay true.
"""

from __future__ import annotations


def install_extra_hint(extra: str) -> str:
    """Both supported ways to obtain *extra*, host install and image rebuild.

    Args:
        extra: the ``[project.optional-dependencies]`` key, e.g. ``"postgres"``.

    Returns:
        A remedy clause for appending to a failure message.
    """
    return (
        f"host: pip install 'nautilus-rkm[{extra}]'; "
        f'image: docker build --build-arg EXTRAS="--extra {extra}" . '
        "(the published image installs --extra otel only, and has no shell or pip "
        "to add to it)"
    )
