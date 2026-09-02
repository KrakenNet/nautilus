# pyright: reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false
"""WAVE ops15 — a running broker never re-read its config, and could not be told to.

``grep -rn 'SIGHUP' nautilus/`` returned **zero**: the only way to change which
sources a broker knows or which rules decide was to stop the process. Every
edit to a mounted ConfigMap therefore cost a rollout, and a rollout of a
single-writer broker is a gap in service, not a rolling one.

The tests below are the four questions an operator asks of a reload, plus the
two that make it safe to have one at all:

* a valid edit is adopted, in the running process, without a restart;
* an unparseable one is refused **in the words ``serve`` refuses it in**, a
  refusal record is written, and the old config keeps answering;
* a key that is only read at startup is refused by name rather than
  half-applied — the audit sink, the key ring and the session store are what
  makes this product single-writer and a reload must not pretend otherwise;
* a request already running finishes on the sources and the rules it started
  with, whatever lands mid-flight.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import signal
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import yaml

if TYPE_CHECKING:
    from collections.abc import Iterator

    from nautilus.core.broker import Broker

pytestmark = [pytest.mark.integration]


# ----------------------------------------------------------------------
# Fixture config — two sources, so a reload has something to add and drop
# ----------------------------------------------------------------------


def _source(source_id: str, *, data_type: str) -> dict[str, Any]:
    return {
        "id": source_id,
        "type": "static",
        "description": f"ops15 fixture {source_id}",
        "classification": "unclassified",
        "data_types": [data_type],
        "allowed_purposes": ["threat-analysis"],
        "rows": [{"id": 1, "body": source_id}],
    }


def _config(tmp_path: Path, *, sources: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "sources": sources,
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "attestation": {"enabled": False},
    }
    doc.update(extra)
    return doc


def _write(path: Path, doc: dict[str, Any]) -> Path:
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return path


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "nautilus.yaml",
        _config(tmp_path, sources=[_source("alpha", data_type="cve")]),
    )


@pytest.fixture
def broker(config_path: Path) -> Iterator[Broker]:
    from nautilus.cli.serve import broker_for_serve

    built = broker_for_serve(config_path, air_gapped=False)
    try:
        yield built
    finally:
        with contextlib.suppress(Exception):
            asyncio.run(built.aclose())


def _audit_events(config_path: Path) -> list[dict[str, Any]]:
    """Every audit line written so far, decoded back to the Nautilus entry."""
    from nautilus.audit.logger import NAUTILUS_METADATA_KEY

    path = config_path.parent / "audit.jsonl"
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record: dict[str, Any] = json.loads(line)
        blob = (record.get("metadata") or {}).get(NAUTILUS_METADATA_KEY)
        if blob:
            out.append(json.loads(blob))
    return out


# ----------------------------------------------------------------------
# 1. A valid config is adopted, live
# ----------------------------------------------------------------------


def test_a_valid_edit_is_adopted_without_restarting(broker: Broker, config_path: Path) -> None:
    """The new sources and the new rules are the ones the next request uses."""
    from nautilus.cli.serve import reload_config

    assert [s.id for s in broker.sources] == ["alpha"]

    _write(
        config_path,
        _config(
            config_path.parent,
            sources=[_source("alpha", data_type="cve"), _source("beta", data_type="asset")],
        ),
    )
    assert asyncio.run(reload_config(broker, config_path, air_gapped=False)) is True

    assert [s.id for s in broker.sources] == ["alpha", "beta"]
    assert broker.config.sources[1].data_types == ["asset"]
    events = [e for e in _audit_events(config_path) if e["event_type"] == "config_reloaded"]
    assert events, "an adopted reload must leave a receipt"
    assert events[-1]["raw_intent"] == "adopted sources"


def test_an_unchanged_source_keeps_the_adapter_it_already_connected(
    broker: Broker, config_path: Path
) -> None:
    """A reload must not drop a live pool for a source nobody edited."""
    from nautilus.cli.serve import reload_config

    before = broker._adapters["alpha"]
    _write(
        config_path,
        _config(
            config_path.parent,
            sources=[_source("alpha", data_type="cve"), _source("beta", data_type="asset")],
        ),
    )
    assert asyncio.run(reload_config(broker, config_path, air_gapped=False)) is True
    assert broker._adapters["alpha"] is before
    assert broker._adapters["beta"] is not before


def _rule_names(broker: Broker) -> set[str]:
    """The names of every rule the engine is running right now."""
    return {str(rule["name"]) for rule in broker.rules_in_force()}


def _write_rule(rules_dir: Path, name: str) -> None:
    """One user rule, in the shape ``nautilus/rules/rules/*.yaml`` ships."""
    (rules_dir / "extra.yaml").write_text(
        yaml.safe_dump(
            {
                "module": "nautilus-routing",
                "ruleset": "ops15-user",
                "version": "1.0",
                "rules": [
                    {
                        "name": name,
                        "description": "ops15 fixture rule",
                        "salience": 10,
                        "when": [
                            {
                                "template": "source",
                                "conditions": [{"slot": "id", "bind": "?sid"}],
                            }
                        ],
                        "then": {"action": "allow", "reason": name},
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def test_a_rule_file_edit_arrives_even_though_the_rules_stanza_did_not_change(
    broker: Broker, config_path: Path
) -> None:
    """``rules`` means the rule files, not only the stanza that points at them."""
    from nautilus.cli.serve import reload_config

    rules_dir = config_path.parent / "rules"
    rules_dir.mkdir()
    doc = _config(
        config_path.parent,
        sources=[_source("alpha", data_type="cve")],
        rules={"user_rules_dirs": [str(rules_dir)]},
    )
    _write_rule(rules_dir, "ops15-first")
    _write(config_path, doc)
    assert asyncio.run(reload_config(broker, config_path, air_gapped=False)) is True
    first_hash = broker.ruleset_hash
    assert "ops15-first" in _rule_names(broker)

    _write_rule(rules_dir, "ops15-second")
    assert asyncio.run(reload_config(broker, config_path, air_gapped=False)) is True
    assert broker.ruleset_hash != first_hash
    assert "ops15-second" in _rule_names(broker)
    assert "ops15-first" not in _rule_names(broker)


# ----------------------------------------------------------------------
# 2. A refused config leaves the running one serving
# ----------------------------------------------------------------------


def test_an_unparseable_config_is_refused_and_the_old_one_keeps_serving(
    broker: Broker, config_path: Path
) -> None:
    from nautilus.cli.serve import reload_config

    config_path.write_text("sources: [ this is not: valid: yaml\n", encoding="utf-8")
    assert asyncio.run(reload_config(broker, config_path, air_gapped=False)) is False

    assert [s.id for s in broker.sources] == ["alpha"]
    assert broker.closed is False
    refusals = [e for e in _audit_events(config_path) if e["event_type"] == "config_reload_refused"]
    assert refusals, "a refused reload must leave a receipt"
    assert refusals[-1]["raw_intent"].startswith("invalid config:")


def test_the_reload_refuses_in_the_same_words_serve_refuses_in(
    broker: Broker, config_path: Path, tmp_path: Path
) -> None:
    """The reload validator IS ``serve``'s. Byte-identical, not merely similar.

    Anything less and a config blessed here is refused at the next restart, or
    the reverse -- which is the failure mode ``broker_for_serve``'s own
    docstring names as worse than having no check at all.
    """
    from nautilus.cli.serve import ConfigRefusedError, broker_for_serve, reload_config

    broken = [
        # unknown key -> pydantic rejects
        _config(tmp_path, sources=[], rules={"user_rules_dirs": [], "nope": 1}),
        # unknown source type
        _config(tmp_path, sources=[{**_source("alpha", data_type="cve"), "type": "quantum"}]),
        # classification the hierarchy does not define
        _config(
            tmp_path,
            sources=[{**_source("alpha", data_type="cve"), "classification": "tpo-secret"}],
        ),
        # chained audit with no key to sign with
        _config(tmp_path, sources=[], audit={"path": str(tmp_path / "a.jsonl"), "chained": True}),
    ]
    for index, doc in enumerate(broken):
        path = _write(tmp_path / f"broken-{index}.yaml", doc)
        with pytest.raises(ConfigRefusedError) as caught:
            broker_for_serve(path, air_gapped=False)
        serve_words = str(caught.value)

        _write(config_path, doc)
        assert asyncio.run(reload_config(broker, config_path, air_gapped=False)) is False
        refusals = [
            e for e in _audit_events(config_path) if e["event_type"] == "config_reload_refused"
        ]
        # Same failure, same sentence -- only the path differs, and it is the
        # path each was actually asked about.
        assert refusals[-1]["raw_intent"] == serve_words.replace(str(path), str(config_path))


@pytest.mark.parametrize(
    ("stanza", "expected"),
    [
        ({"audit": {"path": "./elsewhere.jsonl"}}, "audit"),
        ({"session_tokens": {"enabled": True}}, "session_tokens"),
        ({"session_store": {"backend": "sqlite"}}, "session_store.backend"),
        ({"api": {"max_concurrent_requests": 8}}, "api"),
        ({"analysis": {"keyword_map": {"cve": ["cve"]}}}, "analysis"),
    ],
)
def test_a_startup_only_key_is_refused_by_name_not_half_applied(
    broker: Broker, config_path: Path, stanza: dict[str, Any], expected: str
) -> None:
    """The single-writer parts need a restart, and the reload says which ones."""
    from nautilus.cli.serve import reload_config

    doc = _config(config_path.parent, sources=[_source("alpha", data_type="cve")])
    doc.update(stanza)
    _write(config_path, doc)

    assert asyncio.run(reload_config(broker, config_path, air_gapped=False)) is False
    refusals = [e for e in _audit_events(config_path) if e["event_type"] == "config_reload_refused"]
    assert expected in refusals[-1]["raw_intent"]
    assert "restart" in refusals[-1]["raw_intent"].lower()
    # And nothing moved.
    assert broker.config.audit.path == str(config_path.parent / "audit.jsonl")
    assert broker.config.session_tokens.enabled is False
    assert broker.config.session_store.backend == "memory"


def test_the_two_live_session_store_limits_are_reloadable(
    broker: Broker, config_path: Path
) -> None:
    """They are read per request, so nothing has to be rebuilt to adopt them."""
    from nautilus.cli.serve import reload_config

    doc = _config(
        config_path.parent,
        sources=[_source("alpha", data_type="cve")],
        session_store={"lock_timeout_s": 3.5, "purpose_ttl_seconds": 900},
    )
    _write(config_path, doc)
    assert asyncio.run(reload_config(broker, config_path, air_gapped=False)) is True
    assert broker.config.session_store.lock_timeout_s == 3.5
    assert broker.config.session_store.purpose_ttl_seconds == 900


# ----------------------------------------------------------------------
# 3. In-flight requests finish on the config they started with
# ----------------------------------------------------------------------


def test_a_request_in_flight_finishes_on_the_config_it_started_with(
    broker: Broker, config_path: Path
) -> None:
    """Reload lands mid-request; the request must not see the new sources."""
    from nautilus.cli.serve import reload_config

    seen: list[list[str]] = []
    entered = asyncio.Event()
    release = asyncio.Event()

    async def run() -> None:
        async def observer() -> None:
            # Stands in for the adapter fan-out: a real await inside the
            # request, with a reload completing while it is suspended.
            with broker._pinned_generation():
                entered.set()
                await release.wait()
                seen.append([s.id for s in broker._registry])

        task = asyncio.ensure_future(observer())
        await entered.wait()
        _write(
            config_path,
            _config(
                config_path.parent,
                sources=[
                    _source("alpha", data_type="cve"),
                    _source("beta", data_type="asset"),
                ],
            ),
        )
        reload_task = asyncio.ensure_future(reload_config(broker, config_path, air_gapped=False))
        # The swap itself does not wait for anyone: it is live for a caller
        # who starts now, while the suspended request is still mid-flight.
        for _ in range(500):
            await asyncio.sleep(0.01)
            if [s.id for s in broker._registry] == ["alpha", "beta"]:
                break
        assert [s.id for s in broker._registry] == ["alpha", "beta"]
        assert not reload_task.done(), "the reload finished without waiting for the request"
        release.set()
        await task
        assert await reload_task is True

    asyncio.run(run())
    assert seen == [["alpha"]], "the pinned request read the reloaded registry"
    # ...and a caller who starts after it sees the new one.
    assert [s.id for s in broker._registry] == ["alpha", "beta"]


def test_the_retired_generation_is_closed_only_after_it_drains(
    broker: Broker, config_path: Path
) -> None:
    """A dropped source's adapter must outlive the request still using it."""
    from nautilus.cli.serve import reload_config

    closed: list[str] = []
    original = broker._adapters["alpha"]

    async def _record_close() -> None:
        closed.append("alpha")

    object.__setattr__(original, "close", _record_close)

    entered = asyncio.Event()
    release = asyncio.Event()
    reload_done: list[bool] = []

    async def run() -> None:
        async def holder() -> None:
            entered.set()
            await release.wait()

        with broker._pinned_generation():
            task = asyncio.ensure_future(holder())
            await entered.wait()
            _write(
                config_path,
                _config(config_path.parent, sources=[_source("beta", data_type="asset")]),
            )
            reload_task = asyncio.ensure_future(
                reload_config(broker, config_path, air_gapped=False)
            )
            # Let the reload get as far as it can while the pin is held.
            for _ in range(500):
                await asyncio.sleep(0.01)
                if [s.id for s in broker._generation.registry] == ["beta"]:
                    break
            assert [s.id for s in broker._generation.registry] == ["beta"]
            assert not closed, "the adapter was closed while a request still held it"
            reload_done.append(reload_task.done())
            release.set()
            await task
        assert await reload_task is True

    asyncio.run(run())
    assert reload_done == [False], "the reload returned before the old generation drained"
    assert closed == ["alpha"], "the retired adapter was never closed"


# ----------------------------------------------------------------------
# 4. The signal is actually wired, and the process survives a bad file
# ----------------------------------------------------------------------


def test_sighup_is_wired_on_the_serving_loop(broker: Broker, config_path: Path) -> None:
    from nautilus.cli.serve import _install_reload_handler

    async def run() -> bool:
        _install_reload_handler(broker, config_path, air_gapped=False)
        loop = asyncio.get_running_loop()
        _write(
            config_path,
            _config(
                config_path.parent,
                sources=[_source("alpha", data_type="cve"), _source("beta", data_type="asset")],
            ),
        )
        signal.raise_signal(signal.SIGHUP)
        for _ in range(200):
            await asyncio.sleep(0.01)
            if [s.id for s in broker.sources] == ["alpha", "beta"]:
                loop.remove_signal_handler(signal.SIGHUP)
                return True
        loop.remove_signal_handler(signal.SIGHUP)
        return False

    assert asyncio.run(run()) is True
