"""LineageStore — rule-version lineage DAG (#35.10).

File-per-rule-version persistence at
``.nautilus/rkm/lineage/<rule_name>.v<version>.json``. The DAG has no
cycles (Data invariant #4); :meth:`LineageStore.insert` walks
``derived_from`` ancestors before write and raises
:class:`LineageCycleError` on detection.
"""

from __future__ import annotations

import contextlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal


class LineageCycleError(Exception):
    """Raised when inserting a lineage record would create a DAG cycle."""

    def __init__(self, cycle_path: list[str]) -> None:
        super().__init__(" -> ".join(cycle_path))
        self.cycle_path: list[str] = cycle_path


@dataclass(frozen=True)
class LineageRecord:
    """One rule-version lineage record. AC-35.10.b."""

    rule_name: str
    version: int
    proposer: str
    observation_ids: dict[str, Any]
    sandbox_results: dict[str, Any]
    approver: str | None
    derived_from: tuple[str, ...]
    promoted_at: datetime
    retired_at: datetime | None = None
    retire_reason: str | None = None
    retire_reviewer: str | None = None


def _record_to_dict(record: LineageRecord) -> dict[str, Any]:
    d = asdict(record)
    d["promoted_at"] = record.promoted_at.isoformat()
    if record.retired_at is not None:
        d["retired_at"] = record.retired_at.isoformat()
    d["derived_from"] = list(record.derived_from)
    return d


def _record_from_dict(d: dict[str, Any]) -> LineageRecord:
    d = dict(d)
    promoted_raw = d["promoted_at"]
    if isinstance(promoted_raw, str):
        dt = datetime.fromisoformat(promoted_raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        d["promoted_at"] = dt
    retired_raw = d.get("retired_at")
    if isinstance(retired_raw, str):
        rt = datetime.fromisoformat(retired_raw)
        if rt.tzinfo is None:
            rt = rt.replace(tzinfo=UTC)
        d["retired_at"] = rt
    d["derived_from"] = tuple(d.get("derived_from", []))
    return LineageRecord(**d)


class LineageStore:
    """Persisted lineage DAG with cycle-safe insert. AC-35.10.b/c/d.

    If ``store_dir`` is provided, records are persisted to
    ``<store_dir>/<rule_name>.v<version>.json``.
    If ``store_dir`` is None, an in-memory dict is used (test/default mode).
    """

    def __init__(self, store_dir: Path | None = None) -> None:
        self._store_dir = store_dir
        if store_dir is not None:
            store_dir.mkdir(parents=True, exist_ok=True)
        # In-memory store: key = (rule_name, version)
        self._mem: dict[tuple[str, int], LineageRecord] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_path(self, rule_name: str, version: int) -> Path:
        assert self._store_dir is not None  # noqa: S101
        return self._store_dir / f"{rule_name}.v{version}.json"

    def _write_record(self, record: LineageRecord) -> None:
        if self._store_dir is None:
            return
        path = self._record_path(record.rule_name, record.version)
        data = json.dumps(_record_to_dict(record), separators=(",", ":"), default=str)
        with path.open("w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

    def _load_record(self, rule_name: str, version: int) -> LineageRecord | None:
        if self._store_dir is None:
            return self._mem.get((rule_name, version))
        path = self._record_path(rule_name, version)
        if not path.exists():
            return None
        return _record_from_dict(json.loads(path.read_text(encoding="utf-8")))

    def _all_records(self) -> list[LineageRecord]:
        """Return all records across all rule names and versions."""
        if self._store_dir is None:
            return list(self._mem.values())
        records: list[LineageRecord] = []
        for path in self._store_dir.glob("*.json"):
            with contextlib.suppress(Exception):
                records.append(_record_from_dict(json.loads(path.read_text(encoding="utf-8"))))
        return records

    def _store_record(self, record: LineageRecord) -> None:
        """Persist to mem + disk."""
        self._mem[(record.rule_name, record.version)] = record
        self._write_record(record)

    # ------------------------------------------------------------------
    # Cycle detection
    # ------------------------------------------------------------------

    def _check_no_cycle(self, new_record: LineageRecord) -> None:
        """DFS from new_record.rule_name following derived_from edges.

        Raises :class:`LineageCycleError` if any ancestor equals new_record.rule_name.
        """
        # Build a temporary snapshot of the graph including the new record.
        # Map rule_name -> set of parent rule_names (via latest version).
        parents_of: dict[str, set[str]] = {}
        for rec in self._all_records():
            if rec.rule_name not in parents_of:
                parents_of[rec.rule_name] = set()
            parents_of[rec.rule_name].update(rec.derived_from)
        # Add the prospective new record (overwrite for this rule_name)
        parents_of[new_record.rule_name] = set(new_record.derived_from)

        # DFS: start from each parent of new_record, see if we reach new_record.rule_name
        target = new_record.rule_name
        for start in new_record.derived_from:
            visited: set[str] = set()
            stack: list[tuple[str, list[str]]] = [(start, [target, start])]
            while stack:
                node, path = stack.pop()
                if node == target:
                    raise LineageCycleError(path)
                if node in visited:
                    continue
                visited.add(node)
                for parent in parents_of.get(node, set()):
                    stack.append((parent, [*path, parent]))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def insert(self, record: LineageRecord) -> None:
        """Persist. Raises :class:`LineageCycleError` on DAG cycle (invariant #4)."""
        self._check_no_cycle(record)
        self._store_record(record)

    def get(self, rule_name: str, version: int | None = None) -> LineageRecord | None:
        """Fetch by ``(rule_name, version)`` or latest if version is None."""
        if version is not None:
            return self._load_record(rule_name, version)
        # Latest: highest version number
        all_versions = self.history(rule_name)
        return all_versions[-1] if all_versions else None

    def history(self, rule_name: str) -> list[LineageRecord]:
        """All versions for a rule, oldest first."""
        if self._store_dir is None:
            records = [r for r in self._mem.values() if r.rule_name == rule_name]
        else:
            records = []
            for path in self._store_dir.glob(f"{rule_name}.v*.json"):
                with contextlib.suppress(Exception):
                    records.append(
                        _record_from_dict(json.loads(path.read_text(encoding="utf-8")))
                    )
        return sorted(records, key=lambda r: r.version)

    def descendants(self, rule_name: str) -> list[str]:
        """All active rules listing ``rule_name`` in ``derived_from``. AC-35.10.c."""
        seen: set[str] = set()
        result: list[str] = []
        for rec in self._all_records():
            if rule_name in rec.derived_from and rec.rule_name not in seen:
                seen.add(rec.rule_name)
                result.append(rec.rule_name)
        return result

    def mark_retired(
        self,
        rule_name: str,
        *,
        version: int,
        reason: str,
        reviewer: str,
        cascade: Literal["none", "cascade", "orphan-children"],
    ) -> list[str]:
        """Retire ``(rule_name, version)``. Returns ``affected_descendants`` names. AC-35.10.d."""
        record = self._load_record(rule_name, version)
        if record is None:
            raise KeyError(f"lineage record not found: {rule_name} v{version}")
        from dataclasses import replace
        updated = replace(
            record,
            retired_at=datetime.now(UTC),
            retire_reason=reason,
            retire_reviewer=reviewer,
        )
        self._store_record(updated)
        affected = self.descendants(rule_name)
        return affected

    def list_by_derived_from(self, parent_id: str) -> tuple[LineageRecord, ...]:
        """All records listing ``parent_id`` in ``derived_from``. AC-35.10.c."""
        return tuple(r for r in self._all_records() if parent_id in r.derived_from)


__all__ = ["LineageCycleError", "LineageRecord", "LineageStore"]
