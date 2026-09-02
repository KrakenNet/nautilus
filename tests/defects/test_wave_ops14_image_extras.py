"""WAVE OPS14 — the image could not run the backends the docs spend the most words on.

An external operator, given only ``docs/``, configured the session-store backend the
reference documentation covers at length and got this out of the published image::

    File "/app/nautilus/core/session_pg.py", line 229, in setup
        import asyncpg  # pyright: ignore[reportMissingTypeStubs]
    ModuleNotFoundError: No module named 'asyncpg'

    ERROR:    Application startup failed. Exiting.

No extra named, no remedy, out of an ASGI lifespan hook. ``analysis.provider.type: local``
answered ``openai extra not installed; install nautilus[llm-openai]`` — a distribution name
that does not exist on PyPI. And the only install guidance in ``docs/`` was
``pip install "nautilus-rkm[postgres,s3]"``, a **host** command: the runtime image is
distroless, with no shell and no package manager, so nothing can be installed into it at all.

The minimal image is deliberate and stays. What is pinned here is the pair of things that
were missing around it:

1. **The failure names a remedy the operator can carry out.** Every "missing optional
   dependency" message ends in :func:`nautilus.extras.install_extra_hint`, which renders
   both routes — the host ``pip install`` and the ``docker build --build-arg EXTRAS=…``
   rebuild that is the only one available inside a distroless image.
2. **The documentation states which extras the published image carries, mechanically.**
   ``docs/how-to/deploying.md`` §1 carries a table of every extra, the distributions it
   installs, and whether the published image has it. A hand-written list is exactly the
   shape of claim this codebase has been bitten by, so the table is held against
   ``pyproject.toml``, against the ``Dockerfile``, and — in the ``docker`` lane — against
   the distributions a freshly built image really contains.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC = REPO_ROOT / "docs" / "how-to" / "deploying.md"
DOCKERFILE = REPO_ROOT / "Dockerfile"
PYPROJECT = REPO_ROOT / "pyproject.toml"

#: Extras that are tooling, not runtime: never candidates for a deployed image, so the
#: operator-facing table does not carry them.
_TOOLING_EXTRAS = frozenset({"dev", "docs"})


def _canonical(name: str) -> str:
    """PEP 503 canonical distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_name(requirement: str) -> str:
    """``"influxdb-client>=1.40"`` -> ``"influxdb-client"``."""
    return _canonical(re.split(r"[<>=!~;\[ ]", requirement.strip(), maxsplit=1)[0])


def _pyproject_extras() -> dict[str, set[str]]:
    """Every extra ``pyproject.toml`` declares -> the distributions it pulls."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    optional = data["project"]["optional-dependencies"]
    return {
        extra: {_requirement_name(req) for req in reqs}
        for extra, reqs in optional.items()
        if extra not in _TOOLING_EXTRAS
    }


def _dockerfile_default_extras() -> set[str]:
    """The extras a default ``docker build .`` installs.

    ``uv sync`` appears twice — once without the project, once with it — and the two must
    agree, because ``uv sync`` makes the environment match the request exactly and the
    second call would uninstall anything the first added that it does not repeat.
    """
    text = DOCKERFILE.read_text(encoding="utf-8").replace("\\\n", " ")

    arg = re.findall(r"^ARG\s+EXTRAS=(.*)$", text, re.M)
    assert arg, "Dockerfile no longer has an `ARG EXTRAS` — the documented rebuild route is gone"
    assert len(arg) == 1, f"more than one `ARG EXTRAS` default to reason about: {arg}"
    assert arg[0].strip().strip('"').strip("'") == "", (
        f"`ARG EXTRAS` defaults to {arg[0]!r}, so the default image is no longer driver-free; "
        "either restore the empty default or update the extras table in docs/how-to/deploying.md"
    )

    syncs = re.findall(r"^RUN\s+uv\s+sync\s+(.*)$", text, re.M)
    assert syncs, "no `RUN uv sync` line in the Dockerfile to read the extras from"
    per_line = [set(re.findall(r"--extra\s+([A-Za-z0-9._-]+)", line)) for line in syncs]
    assert all(extras == per_line[0] for extras in per_line), (
        f"the `uv sync` invocations disagree about extras: {per_line}. The second call "
        "would uninstall what the first installed."
    )
    return per_line[0]


def _doc_extras_table() -> dict[str, tuple[bool, set[str]]]:
    """The deploying-guide table -> ``{extra: (in the published image, distributions)}``."""
    text = DOC.read_text(encoding="utf-8")
    start = text.index("### Extras, and what the published image carries")
    body = text[start:]
    end = body.find("\n## ", 1)
    if end != -1:
        body = body[:end]

    table: dict[str, tuple[bool, set[str]]] = {}
    for line in body.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if "|" in line else []
        if len(cells) != 4 or not cells[0].startswith("`"):
            continue
        extra = cells[0].strip("`")
        shipped_cell = cells[1].replace("*", "").strip().lower()
        assert shipped_cell in {"yes", "no"}, (
            f"row {extra!r} answers {cells[1]!r} to 'in the published image'; "
            "the column has to be a plain yes or no for this test to hold it to anything"
        )
        dists = {_canonical(m) for m in re.findall(r"`([^`]+)`", cells[2])}
        table[extra] = (shipped_cell == "yes", dists)
    assert table, f"no extras table parsed out of {DOC}"
    return table


def _extras_named_in_failure_messages() -> set[str]:
    """Every extra the source tells an operator to install, read out of the AST.

    Two call shapes carry a literal: ``install_extra_hint("llm-openai")`` at the sites that
    know their own dependency, and ``missing_driver_adapter(type, "extra", exc)``, whose
    stand-in renders the hint for a source driver.
    """
    found: set[str] = set()
    for path in sorted((REPO_ROOT / "nautilus").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id == "install_extra_hint" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.add(arg.value)
            elif node.func.id == "missing_driver_adapter" and len(node.args) >= 2:
                arg = node.args[1]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.add(arg.value)
    assert found, "no extra is named in any failure message — the AST walk found nothing"
    return found


# ---------------------------------------------------------------------------
# The documentation states what the image carries, and cannot drift from it
# ---------------------------------------------------------------------------


def test_the_extras_table_covers_every_extra_the_project_declares() -> None:
    """An extra missing from the table is an operator with no way to learn it exists.

    This is not hypothetical: the sentence the table replaced listed six source drivers and
    omitted `llm-openai` and `llm-anthropic`, so `analysis.provider` had no documented
    extra at all while the reference documentation described three providers.
    """
    documented = set(_doc_extras_table())
    declared = set(_pyproject_extras())
    assert documented == declared, (
        f"docs/how-to/deploying.md and pyproject.toml disagree about which extras exist. "
        f"Only in pyproject: {sorted(declared - documented)}. "
        f"Only in the docs: {sorted(documented - declared)}."
    )


def test_the_table_names_the_distributions_each_extra_really_installs() -> None:
    """'What does `--extra s3` actually put in my image' is answerable from the page."""
    table = _doc_extras_table()
    declared = _pyproject_extras()
    wrong = {
        extra: (dists, declared[extra])
        for extra, (_shipped, dists) in table.items()
        if dists != declared[extra]
    }
    assert not wrong, (
        "the extras table names distributions the extra does not install, or omits ones "
        f"it does (extra: documented vs declared): {wrong}"
    )


def test_the_shipped_column_matches_what_the_dockerfile_installs() -> None:
    """The claim 'the published image carries only `otel`' is checked, not asserted."""
    table = _doc_extras_table()
    documented_shipped = {extra for extra, (shipped, _d) in table.items() if shipped}
    built = _dockerfile_default_extras()
    assert documented_shipped == built, (
        f"the extras table says the published image carries {sorted(documented_shipped)}; "
        f"a default `docker build .` installs {sorted(built)}. One of the two is lying to "
        "an operator deciding whether their config can run."
    )


def test_every_extra_a_failure_message_names_is_in_the_table() -> None:
    """You cannot add a 'install the X extra' message for an X the docs never mention."""
    named = _extras_named_in_failure_messages()
    documented = set(_doc_extras_table())
    assert named <= documented, (
        f"failure messages tell operators to install {sorted(named - documented)}, which "
        "the extras table in docs/how-to/deploying.md does not list"
    )


# ---------------------------------------------------------------------------
# The failure names a remedy a distroless operator can actually perform
# ---------------------------------------------------------------------------


def test_the_install_hint_offers_the_rebuild_and_not_only_pip() -> None:
    """``pip install`` on the host is not a step available inside the shipped image."""
    from nautilus.extras import install_extra_hint

    hint = install_extra_hint("postgres")
    assert "pip install 'nautilus-rkm[postgres]'" in hint, hint
    assert 'docker build --build-arg EXTRAS="--extra postgres"' in hint, hint
    assert "no shell or pip" in hint, (
        "the hint gives a host command and an image command without saying which runtime "
        f"can take which, so the operator has to guess: {hint}"
    )


def test_a_postgres_session_store_without_asyncpg_names_the_extra_and_the_rebuild(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reported defect: a bare ``ModuleNotFoundError`` out of a lifespan hook.

    ``sys.modules["asyncpg"] = None`` is how the interpreter itself records "this import
    is blocked", so the constructor takes exactly the path it takes on the shipped image.
    """
    from nautilus.config.loader import ConfigError
    from nautilus.core.session_pg import PostgresSessionStore

    monkeypatch.setitem(__import__("sys").modules, "asyncpg", None)

    with pytest.raises(ConfigError) as caught:
        PostgresSessionStore("postgresql://user:pw@db.internal:5432/sessions")

    message = str(caught.value)
    assert "session_store.backend=postgres" in message, message
    assert "'postgres' extra" in message, message
    assert 'docker build --build-arg EXTRAS="--extra postgres"' in message, message
    # And it offers the configuration change that needs no driver at all.
    assert "sqlite" in message and "memory" in message, message


def test_a_postgres_session_store_refuses_rather_than_degrading_without_a_driver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``on_failure`` degrades an *unreachable* store; an absent driver never returns.

    Falling back here would serve the exposure ledger out of process memory for the life
    of the pod — the per-replica ledger a shared session store exists to prevent — and the
    only signal would be a mode field nobody is reading yet.
    """
    from nautilus.config.loader import ConfigError
    from nautilus.core.session_pg import PostgresSessionStore

    monkeypatch.setitem(__import__("sys").modules, "asyncpg", None)

    for policy in ("fallback_memory", "fallback_sqlite"):
        with pytest.raises(ConfigError):
            PostgresSessionStore("postgresql://db.internal:5432/s", on_failure=policy)  # type: ignore[arg-type]


def test_the_local_inference_provider_says_why_it_wants_an_openai_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``analysis.provider.type: local`` failing with 'openai extra not installed' reads
    like a bug in the broker to an operator who deliberately chose a local model."""
    import nautilus.analysis.llm.local_provider as local_mod
    from nautilus.analysis.llm.base import LLMProviderError

    monkeypatch.setattr(local_mod, "AsyncOpenAI", None)

    with pytest.raises(LLMProviderError) as caught:
        local_mod.LocalInferenceProvider(
            base_url="http://127.0.0.1:8080/v1", model="qwen", timeout_s=2.0
        )

    message = str(caught.value)
    assert "type=local" in message, message
    assert "OpenAI wire protocol" in message, message
    assert 'docker build --build-arg EXTRAS="--extra llm-openai"' in message, message


def test_a_source_whose_driver_is_missing_names_the_rebuild_too() -> None:
    """The startup ``ConfigError`` for a source type used to end at ``pip install``."""
    from nautilus.adapters import missing_driver_adapter

    stand_in = missing_driver_adapter("s3", "s3", ImportError("No module named 'aiobotocore'"))
    hint = stand_in.install_hint  # type: ignore[attr-defined]
    assert 'docker build --build-arg EXTRAS="--extra s3"' in hint, hint


# ---------------------------------------------------------------------------
# Ground truth: what a built image actually contains
# ---------------------------------------------------------------------------

_DOCKER = shutil.which("docker")
_IMAGE_TAG = "nautilus:test-extras"

_PROBE = (
    "import importlib.metadata as m, json, sys\n"
    "out = {}\n"
    "for name in sys.argv[1:]:\n"
    "    try:\n"
    "        m.distribution(name)\n"
    "        out[name] = True\n"
    "    except Exception:\n"
    "        out[name] = False\n"
    "print(json.dumps(out))\n"
)


def _docker_daemon_live() -> bool:
    if _DOCKER is None:
        return False
    try:
        probe = subprocess.run(  # noqa: S603 — trusted binary discovered via shutil.which
            [_DOCKER, "info", "--format", "{{.ServerVersion}}"],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0 and bool(probe.stdout.strip())


@pytest.mark.docker
@pytest.mark.integration
def test_the_built_image_carries_exactly_the_extras_the_table_claims() -> None:
    """The table is held against the artifact, not against the Dockerfile that made it.

    Reading the ``Dockerfile`` proves what was *asked for*. This asks the image. A
    transitive dependency, a lockfile edit or a base-image change can put a driver in the
    image nobody asked for — and an operator reading "no drivers" would then be told the
    opposite of what they hold.
    """
    if not _docker_daemon_live():
        pytest.skip("docker daemon not available")

    build = subprocess.run(  # noqa: S603 — trusted binary discovered via shutil.which
        [_DOCKER or "docker", "build", "--target", "runtime", "-t", _IMAGE_TAG, "."],
        check=False,
        capture_output=True,
        cwd=str(REPO_ROOT),
        timeout=900,
    )
    assert build.returncode == 0, (
        f"docker build failed:\n{build.stderr.decode('utf-8', errors='replace')}"
    )

    table = _doc_extras_table()
    expected_present: set[str] = set()
    expected_absent: set[str] = set()
    for _extra, (shipped, dists) in table.items():
        (expected_present if shipped else expected_absent).update(dists)
    # An extra can share a distribution with a shipped one; presence wins.
    expected_absent -= expected_present
    assert expected_present and expected_absent, (
        "the table claims either everything or nothing ships, which would make this "
        "assertion vacuous"
    )

    probe = subprocess.run(  # noqa: S603 — trusted binary
        [
            _DOCKER or "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/app/.venv/bin/python",
            _IMAGE_TAG,
            "-c",
            _PROBE,
            *sorted(expected_present | expected_absent),
        ],
        check=False,
        capture_output=True,
        timeout=120,
    )
    assert probe.returncode == 0, (
        f"could not read installed distributions out of the image: "
        f"{probe.stderr.decode('utf-8', errors='replace')}"
    )
    installed: dict[str, bool] = json.loads(probe.stdout.decode("utf-8"))

    missing = sorted(name for name in expected_present if not installed[name])
    surplus = sorted(name for name in expected_absent if installed[name])
    assert not missing and not surplus, (
        f"docs/how-to/deploying.md and the image {_IMAGE_TAG} disagree. "
        f"Documented as shipped but absent: {missing}. "
        f"Documented as not shipped but present: {surplus}."
    )
