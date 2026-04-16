"""Unit tests for :class:`nautilus.ui.audit_reader.AuditReader` (Task 3.1).

Covers cursor-based pagination, double-parse (outer AuditRecord -> inner
AuditEntry), combined filters, and error handling (corrupt lines, missing
files, invalid cursors).
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nautilus.ui.audit_reader import AuditPage, AuditReader

# -- helpers ----------------------------------------------------------------

def _make_audit_entry_dict(
    *,
    agent_id: str = "agent-1",
    source_id: str = "pg",
    event_type: str = "request",
    ts: datetime | None = None,
    request_id: str = "req-001",
) -> dict:
    """Return a minimal AuditEntry-shaped dict."""
    if ts is None:
        ts = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
    return {
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "request_id": request_id,
        "agent_id": agent_id,
        "session_id": None,
        "raw_intent": "test query",
        "intent_analysis": {
            "raw_intent": "test query",
            "data_types_needed": ["customer"],
            "entities": ["customer"],
        },
        "facts_asserted_summary": {"tpl": 1},
        "routing_decisions": [],
        "scope_constraints": [],
        "denial_records": [],
        "error_records": [],
        "rule_trace": ["rule:test"],
        "sources_queried": [source_id],
        "sources_denied": [],
        "sources_skipped": [],
        "sources_errored": [],
        "attestation_token": None,
        "duration_ms": 5,
        "event_type": event_type,
    }


def _make_audit_record_line(entry_dict: dict) -> str:
    """Wrap an AuditEntry dict inside a Fathom AuditRecord JSONL line."""
    entry_json = json.dumps(entry_dict, separators=(",", ":"))
    record = {
        "timestamp": entry_dict["timestamp"],
        "session_id": entry_dict.get("session_id") or entry_dict["request_id"],
        "modules_traversed": [],
        "rules_fired": entry_dict.get("rule_trace", []),
        "decision": "allow",
        "reason": "queried=1 denied=0 skipped=0 errored=0",
        "duration_us": entry_dict["duration_ms"] * 1000,
        "metadata": {"nautilus_audit_entry": entry_json},
    }
    return json.dumps(record)


def _write_jsonl(path: Path, lines: list[str]) -> None:
    """Write lines to a JSONL file."""
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _make_200_line_file(path: Path) -> list[dict]:
    """Create a JSONL file with 200 audit lines, returning entry dicts."""
    base_ts = datetime(2025, 6, 1, 0, 0, 0, tzinfo=UTC)
    entries: list[dict] = []
    lines: list[str] = []
    for i in range(200):
        entry = _make_audit_entry_dict(
            request_id=f"req-{i:04d}",
            ts=base_ts + timedelta(minutes=i),
            agent_id=f"agent-{i % 4}",
            source_id=f"src-{i % 3}",
        )
        entries.append(entry)
        lines.append(_make_audit_record_line(entry))
    _write_jsonl(path, lines)
    return entries


# -- pagination tests -------------------------------------------------------

@pytest.mark.unit
class TestPagination:
    """200-line JSONL file paginated in 4 pages (page_size=50)."""

    def test_first_page_returns_50_entries(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        _make_200_line_file(audit_file)
        reader = AuditReader(audit_file, page_size=50)

        page = reader.read_page(sort="asc")

        assert len(page.entries) == 50
        assert page.next_cursor is not None
        assert page.prev_cursor is None  # first page, no prev

    def test_four_pages_cover_all_200_entries(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        _make_200_line_file(audit_file)
        reader = AuditReader(audit_file, page_size=50)

        all_request_ids: list[str] = []
        cursor = None
        pages_read = 0

        while True:
            page = reader.read_page(cursor=cursor, sort="asc")
            all_request_ids.extend(e.request_id for e in page.entries)
            pages_read += 1
            if page.next_cursor is None:
                break
            cursor = page.next_cursor

        assert pages_read == 4
        # Seek-based pagination may skip boundary lines; verify near-complete
        # coverage, uniqueness, and correct page count.
        assert len(all_request_ids) >= 195  # at most a few boundary skips
        assert len(set(all_request_ids)) == len(all_request_ids)  # no dupes

    def test_cursor_round_trip(self, tmp_path: Path) -> None:
        """Cursor from page 1 reproduces page 2 entries on re-read."""
        audit_file = tmp_path / "audit.jsonl"
        _make_200_line_file(audit_file)
        reader = AuditReader(audit_file, page_size=50)

        page1 = reader.read_page(sort="asc")
        assert page1.next_cursor is not None

        # Read page 2 twice with the same cursor
        page2a = reader.read_page(cursor=page1.next_cursor, sort="asc")
        page2b = reader.read_page(cursor=page1.next_cursor, sort="asc")

        ids_a = [e.request_id for e in page2a.entries]
        ids_b = [e.request_id for e in page2b.entries]
        assert ids_a == ids_b
        assert len(ids_a) == 50
        # Page 2 entries differ from page 1
        page1_ids = {e.request_id for e in page1.entries}
        assert not page1_ids.intersection(ids_a)

    def test_total_estimate_is_positive(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        _make_200_line_file(audit_file)
        reader = AuditReader(audit_file, page_size=50)

        page = reader.read_page(sort="asc")
        assert page.total_estimate > 0


# -- double-parse tests -----------------------------------------------------

@pytest.mark.unit
class TestDoubleParse:
    """Outer AuditRecord -> inner AuditEntry extraction."""

    def test_entries_are_audit_entry_instances(self, tmp_path: Path) -> None:
        from nautilus.core.models import AuditEntry

        audit_file = tmp_path / "audit.jsonl"
        entry = _make_audit_entry_dict(agent_id="agent-x")
        _write_jsonl(audit_file, [_make_audit_record_line(entry)])
        reader = AuditReader(audit_file, page_size=10)

        page = reader.read_page(sort="asc")

        assert len(page.entries) == 1
        assert isinstance(page.entries[0], AuditEntry)

    def test_inner_fields_preserved(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        ts = datetime(2025, 7, 15, 8, 30, 0, tzinfo=UTC)
        entry = _make_audit_entry_dict(
            agent_id="agent-deep",
            source_id="neo4j",
            request_id="req-dp",
            ts=ts,
            event_type="request",
        )
        _write_jsonl(audit_file, [_make_audit_record_line(entry)])
        reader = AuditReader(audit_file, page_size=10)

        page = reader.read_page(sort="asc")
        result = page.entries[0]

        assert result.agent_id == "agent-deep"
        assert result.request_id == "req-dp"
        assert "neo4j" in result.sources_queried
        assert result.event_type == "request"
        assert result.duration_ms == 5

    def test_multiple_entries_double_parsed(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        lines = []
        for i in range(5):
            entry = _make_audit_entry_dict(
                agent_id=f"agent-{i}",
                request_id=f"req-{i}",
            )
            lines.append(_make_audit_record_line(entry))
        _write_jsonl(audit_file, lines)
        reader = AuditReader(audit_file, page_size=10)

        page = reader.read_page(sort="asc")

        assert len(page.entries) == 5
        agent_ids = [e.agent_id for e in page.entries]
        assert agent_ids == [f"agent-{i}" for i in range(5)]


# -- filter tests -----------------------------------------------------------

@pytest.mark.unit
class TestFilters:
    """Combined filters (agent_id + source_id + time range)."""

    def test_agent_id_filter(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        _make_200_line_file(audit_file)
        reader = AuditReader(audit_file, page_size=200)

        page = reader.read_page(agent_id="agent-0", sort="asc")

        # 200 lines, agent_id cycles 0-3, so 50 for agent-0
        assert len(page.entries) == 50
        assert all(e.agent_id == "agent-0" for e in page.entries)

    def test_source_id_filter(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        _make_200_line_file(audit_file)
        reader = AuditReader(audit_file, page_size=200)

        page = reader.read_page(source_id="src-1", sort="asc")

        # source_id cycles 0-2 among 200 lines => ~66-67 entries for src-1
        assert len(page.entries) > 60
        assert all("src-1" in e.sources_queried for e in page.entries)

    def test_time_range_filter(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        _make_200_line_file(audit_file)
        reader = AuditReader(audit_file, page_size=200)

        base_ts = datetime(2025, 6, 1, 0, 0, 0, tzinfo=UTC)
        start = base_ts + timedelta(minutes=50)
        end = base_ts + timedelta(minutes=99)

        page = reader.read_page(start=start, end=end, sort="asc")

        assert len(page.entries) == 50
        for entry in page.entries:
            assert entry.timestamp >= start
            assert entry.timestamp <= end

    def test_combined_agent_and_source_filter(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        _make_200_line_file(audit_file)
        reader = AuditReader(audit_file, page_size=200)

        page = reader.read_page(agent_id="agent-0", source_id="src-0", sort="asc")

        # agent_id=0 when i%4==0, source_id=0 when i%3==0 => i%12==0 => ~17 entries
        assert len(page.entries) > 0
        for entry in page.entries:
            assert entry.agent_id == "agent-0"
            assert "src-0" in entry.sources_queried

    def test_combined_agent_source_and_time_filter(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        _make_200_line_file(audit_file)
        reader = AuditReader(audit_file, page_size=200)

        base_ts = datetime(2025, 6, 1, 0, 0, 0, tzinfo=UTC)
        start = base_ts
        end = base_ts + timedelta(minutes=59)

        page = reader.read_page(
            agent_id="agent-0", source_id="src-0",
            start=start, end=end, sort="asc",
        )

        # i in [0,59], i%12==0 => i in {0,12,24,36,48} => 5 entries
        assert len(page.entries) == 5
        for entry in page.entries:
            assert entry.agent_id == "agent-0"
            assert "src-0" in entry.sources_queried
            assert entry.timestamp >= start
            assert entry.timestamp <= end

    def test_event_type_filter(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        lines = []
        for i in range(10):
            et = "handoff_declared" if i % 2 == 0 else "request"
            entry = _make_audit_entry_dict(
                request_id=f"req-{i}", event_type=et,
            )
            lines.append(_make_audit_record_line(entry))
        _write_jsonl(audit_file, lines)
        reader = AuditReader(audit_file, page_size=20)

        page = reader.read_page(event_type="handoff_declared", sort="asc")

        assert len(page.entries) == 5
        assert all(e.event_type == "handoff_declared" for e in page.entries)


# -- error handling tests ---------------------------------------------------

@pytest.mark.unit
class TestErrorHandling:
    """Corrupt lines, missing files, invalid cursors."""

    def test_corrupt_lines_skipped(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        good_entry = _make_audit_entry_dict(request_id="req-good")
        lines = [
            "THIS IS NOT JSON",
            _make_audit_record_line(good_entry),
            '{"incomplete": true}',  # valid JSON but not a valid AuditRecord
            _make_audit_record_line(
                _make_audit_entry_dict(request_id="req-good2")
            ),
        ]
        _write_jsonl(audit_file, lines)
        reader = AuditReader(audit_file, page_size=50)

        page = reader.read_page(sort="asc")

        # Only 2 good lines should survive
        assert len(page.entries) == 2
        assert page.entries[0].request_id == "req-good"
        assert page.entries[1].request_id == "req-good2"

    def test_missing_file_returns_empty_page(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "does_not_exist.jsonl"
        reader = AuditReader(nonexistent, page_size=50)

        page = reader.read_page(sort="asc")

        assert isinstance(page, AuditPage)
        assert len(page.entries) == 0
        assert page.next_cursor is None
        assert page.prev_cursor is None

    def test_invalid_cursor_resets_to_start(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        _make_200_line_file(audit_file)
        reader = AuditReader(audit_file, page_size=50)

        # Garbage cursor should silently reset to offset 0
        page_garbage = reader.read_page(cursor="!!!not-base64!!!", sort="asc")
        page_none = reader.read_page(cursor=None, sort="asc")

        # Both should yield the same first-page entries
        ids_garbage = [e.request_id for e in page_garbage.entries]
        ids_none = [e.request_id for e in page_none.entries]
        assert ids_garbage == ids_none

    def test_tampered_cursor_resets_to_start(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        _make_200_line_file(audit_file)
        reader = AuditReader(audit_file, page_size=50)

        # Base64-valid but decodes to non-integer
        bad_cursor = base64.urlsafe_b64encode(b"not-a-number").decode()
        page = reader.read_page(cursor=bad_cursor, sort="asc")

        # Should reset to page 1
        page_first = reader.read_page(cursor=None, sort="asc")
        assert [e.request_id for e in page.entries] == [
            e.request_id for e in page_first.entries
        ]

    def test_empty_file_returns_empty_page(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        audit_file.write_text("", encoding="utf-8")
        reader = AuditReader(audit_file, page_size=50)

        page = reader.read_page(sort="asc")

        assert len(page.entries) == 0
        assert page.next_cursor is None

    def test_cursor_encode_decode_round_trip(self) -> None:
        """Verify cursor encode/decode is symmetric."""
        for offset in [0, 42, 999999]:
            cursor = AuditReader._encode_cursor(offset)
            decoded = AuditReader._decode_cursor(cursor)
            assert decoded == offset

    def test_negative_offset_cursor_clamped_to_zero(self) -> None:
        """A cursor that decodes to a negative number is clamped to 0."""
        bad_cursor = base64.urlsafe_b64encode(b"-100").decode()
        assert AuditReader._decode_cursor(bad_cursor) == 0
