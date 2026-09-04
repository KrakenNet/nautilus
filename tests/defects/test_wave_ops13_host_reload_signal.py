"""WAVE ops13 — the host half of the reload reached whatever it could find.

The sibling file ``test_wave_ops13_reload_reachable.py`` covers the container
path, where the documented signal command named a ``pkill`` the image does not
contain. This is the same defect class on the host path, where the command
existed and hit the wrong processes.

``docs/how-to/operator-guide.md`` documented, at two sites::

    kill -HUP "$(pgrep -f 'nautilus serve')"          # or: systemctl reload nautilus
    nautilus config check /etc/nautilus/nautilus.yaml && kill -HUP "$(pgrep -f 'nautilus serve')"

Measured on this host, not reasoned from the man page:

* **A container process is an ordinary host process.** The runtime image runs
  ``/app/.venv/bin/python -m nautilus serve --config /config/nautilus.yaml
  --bind …``, which contains the literal pattern. A container started from
  ``nautilus:test`` appeared in host ``pgrep -f 'nautilus serve'`` output at the
  host PID ``docker inspect -f '{{.State.Pid}}'`` reports for it. While this
  test was being written the host had *five* brokers matching — four in
  containers, one systemd-style on the host — plus the shell that ran the
  ``pgrep``.
* **``-f`` matches any command line that mentions the string.** The shell
  running the documented command matches itself whenever the command arrives
  non-interactively, which is how it arrives from ``ssh host '…'``,
  ``sudo bash -c '…'`` and an Ansible ``shell:`` task.
* **The quoting does not contain the damage, it hides it.** Two matches expand
  to a single argument::

      $ bash -c "kill -HUP \\"\\$(pgrep -f 'nautilus serve')\\""
      bash: line 1: kill: 2875069
      2875071: arguments must be process or job IDs

  so nothing is signalled and the exit status is 1. Zero matches expand to
  ``kill -HUP ""``: ``bash: kill: '': not a pid or valid job spec``, an error,
  not a no-op. Only the unquoted form actually signals every match — including
  the containerised broker belonging to somebody else.

**Why the alternative in the comment was not one.** ``systemctl reload
nautilus`` reaches exactly the service's main process, because systemd tracks
it. But the unit ``docs/how-to/hardening.md`` publishes had no ``ExecReload=``,
and a unit without one refuses::

    $ systemctl reload nautilus
    Failed to reload nautilus.service: Job type reload is not applicable for unit nautilus.service.

measured at exit ``3`` against a transient unit on this machine. Adding
``ExecReload=/bin/kill -HUP $MAINPID`` makes it work, including under the
``NoNewPrivileges``/``PrivateTmp``/``ProtectSystem=strict``/``ProtectHome``
sandbox that unit sets: the trap fired in the main PID and ``systemctl reload``
exited ``0``.

So both documented ways to reach the reload on a host install were broken, in
opposite directions: the one that ran hit too much, and the one in the comment
did not run.

Scope of the two checks: a ``bash`` block is an instruction, so every command in
it has to be right. Prose is explanation, and the guide now explains *why* the
``pgrep`` form is wrong — quoting the anti-pattern in a sentence is the fix, not
the defect.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# A PID that came from matching a command line, in any of the shapes the shell
# offers: `$(pgrep …)`, backticks, `pidof`, or `ps … | grep …`.
_PATTERN_MATCHERS = re.compile(r"\b(pgrep|pidof)\b|\bps\b[^|]*\|[^|]*\bgrep\b")
# `pkill`/`killall` are a pattern match and a signal in one word.
_PATTERN_KILLERS = re.compile(r"\b(pkill|killall)\b")
_SIGNAL_SENDERS = re.compile(r"(^|[|;&(]|\s)(sudo\s+)?(/\S*/)?kill\b")
_SYSTEMCTL_RELOAD = re.compile(r"\bsystemctl\s+(?:--\S+\s+)*reload\s+(\S+)")


def _blocks(text: str, language: str) -> Iterator[str]:
    """Yield the body of every fenced block written in ``language``."""
    for match in re.finditer(r"^```(\w*)\n(.*?)^```", text, re.MULTILINE | re.DOTALL):
        if match.group(1) == language:
            yield match.group(2)


def _documented_pages() -> list[Path]:
    """Every operator-facing page that can carry a procedure."""
    return [REPO_ROOT / "deploy" / "README.md", *sorted((REPO_ROOT / "docs").rglob("*.md"))]


def _procedure_lines() -> list[tuple[Path, str]]:
    """(page, line) for every command line in a ``bash`` procedure block."""
    out: list[tuple[Path, str]] = []
    for page in _documented_pages():
        for block in _blocks(page.read_text(encoding="utf-8"), "bash"):
            for line in block.replace("\\\n", " ").splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    out.append((page, stripped))
    return out


def test_no_documented_procedure_signals_a_pid_it_found_by_pattern_match() -> None:
    """A signal must be aimed at a process, not at everything that matches a string.

    This is the check that was missing while ``pgrep -f 'nautilus serve'`` sat
    in the operator guide as the host reload procedure. Nothing distinguishes
    the broker under the unit from the broker in a container next to it, or from
    the shell that is running the command, because ``pgrep -f`` reads the same
    ``/proc/*/cmdline`` for all three.
    """
    lines = _procedure_lines()
    assert lines, "found no bash procedure lines at all — the parser stopped matching"

    offenders = [
        (page.relative_to(REPO_ROOT).as_posix(), line)
        for page, line in lines
        if _PATTERN_KILLERS.search(line)
        or (_SIGNAL_SENDERS.search(line) and _PATTERN_MATCHERS.search(line))
    ]
    assert not offenders, (
        "these documented procedures send a signal to whatever a command-line "
        f"pattern happens to match: {offenders}. A container process is an "
        "ordinary host process, so the pattern also finds the containerised "
        "broker; `-f` also finds the shell running the command itself over ssh "
        "or sudo. Use `systemctl reload nautilus`, which systemd aims at the "
        "unit's own $MAINPID, or the PID uvicorn logged at startup."
    )


def _documented_units() -> dict[str, str]:
    """``{unit file name: body}`` for every systemd unit published in the docs.

    A unit block is an ``ini`` fence whose first line names the file it goes to,
    which is how ``hardening.md`` writes it::

        # /etc/systemd/system/nautilus.service
    """
    units: dict[str, str] = {}
    for page in _documented_pages():
        for block in _blocks(page.read_text(encoding="utf-8"), "ini"):
            first = block.splitlines()[0].strip()
            named = re.fullmatch(r"#\s*(\S+\.service)", first)
            if named and "[Service]" in block:
                units[Path(named.group(1)).name] = block
    return units


def test_every_unit_the_docs_tell_an_operator_to_reload_defines_execreload() -> None:
    """``systemctl reload`` is not a signal; it is a unit directive.

    The operator guide offered ``systemctl reload nautilus`` as the alternative
    to the ``pgrep`` line, and the unit the hardening guide publishes had no
    ``ExecReload=``. systemd answers "Job type reload is not applicable for unit
    nautilus.service" and exits 3, so the alternative was not one, and every
    documented route to the ``SIGHUP`` reload on a host install was broken.
    """
    units = _documented_units()
    assert units, (
        "found no systemd unit in the documentation — the operator guide points "
        "at one, so either it was deleted or this parser stopped matching"
    )

    reloaded = {
        (page.relative_to(REPO_ROOT).as_posix(), hit.group(1))
        for page, line in _procedure_lines()
        for hit in [_SYSTEMCTL_RELOAD.search(line)]
        if hit
    }
    assert reloaded, (
        "no documented procedure runs `systemctl reload` any more. If the host "
        "reload moved to another mechanism, this test should move with it — but "
        "check first that the new one is not a command-line pattern match."
    )

    broken: list[tuple[str, str, str]] = []
    for page, target in sorted(reloaded):
        unit = units.get(target if target.endswith(".service") else f"{target}.service")
        if unit is None:
            broken.append((page, target, "no unit file is documented anywhere"))
        elif "ExecReload=" not in unit:
            broken.append((page, target, "the documented unit has no ExecReload="))
        elif "$MAINPID" not in unit:
            broken.append((page, target, "ExecReload= does not target $MAINPID"))
    assert not broken, (
        f"documented `systemctl reload` targets that cannot be reloaded: {broken}. "
        "systemd refuses a reload for a unit with no ExecReload=, and an "
        "ExecReload that does not use $MAINPID is back to guessing which process "
        "to signal. `ExecReload=/bin/kill -HUP $MAINPID` is the one form that "
        "reaches the service's own main process and nothing else."
    )
