"""Attachment-content fetch coverage for :mod:`nautilus.adapters.servicenow`.

The Table API only returns attachment *metadata* rows; the binary itself
lives behind the Attachment API (``/api/now/attachment/<sys_id>/file``).
When a source is configured on the ``sys_attachment`` table AND the scope
pins ``sys_id`` (``=`` or ``IN``), the adapter downloads each pinned
attachment and adds a ``content_b64`` field to the row. Guard rails:

- scope NOT pinned on ``sys_id`` → metadata-only rows, zero binary requests
  (a broad query must never fan out into bulk downloads);
- per-file size cap (metadata pre-check on ``size_bytes`` + post-download
  length check) → ``content_error: 'attachment-too-large'``, no content;
- row-count cap → loud ``AdapterError`` (caller narrows the pin);
- ``sys_id`` from the response is regex-validated before it is interpolated
  into the request path → hostile rows get ``content_error``, no request;
- non-``sys_attachment`` tables are untouched even with a ``sys_id`` pin.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx
import pytest

import nautilus.adapters.servicenow as sn_mod
from nautilus.adapters.base import AdapterError
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.config.models import NoneAuth, SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint

_SYS_ID = "a" * 32
_SYS_ID_2 = "b" * 32
_SYS_ID_3 = "c" * 32
_DOCX_BYTES = b"PK\x03\x04 docx bytes"


def _make_source(table: str = "sys_attachment") -> SourceConfig:
    return SourceConfig(
        id="sn_attach",
        type="servicenow",
        description="SN attachments",
        classification="secret",
        data_types=["document"],
        allowed_purposes=["research"],
        connection="https://dev.service-now.com",
        table=table,
        auth=NoneAuth(),
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="pull a document attachment",
        data_types_needed=["document"],
        entities=[],
        temporal_scope=None,
        estimated_sensitivity=None,
    )


def _pin(sys_id: str = _SYS_ID) -> list[ScopeConstraint]:
    return [ScopeConstraint(source_id="sn_attach", field="sys_id", operator="=", value=sys_id)]


def _meta_row(sys_id: str = _SYS_ID, size: str = "1024") -> dict[str, Any]:
    return {
        "sys_id": sys_id,
        "file_name": "doc.docx",
        "size_bytes": size,
        "content_type": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    }


class _SnTransport:
    """MockTransport handler that serves Table-API metadata + binary files."""

    def __init__(
        self,
        meta_rows: list[dict[str, Any]],
        file_bytes: bytes = _DOCX_BYTES,
    ) -> None:
        self.meta_rows = meta_rows
        self.file_bytes = file_bytes
        self.binary_paths: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/api/now/attachment/") and path.endswith("/file"):
            self.binary_paths.append(path)
            return httpx.Response(200, content=self.file_bytes)
        return httpx.Response(200, json={"result": self.meta_rows})


async def _run(
    transport_handler: _SnTransport,
    scope: list[ScopeConstraint],
    table: str = "sys_attachment",
):
    client = httpx.AsyncClient(
        base_url="https://dev.service-now.com",
        transport=httpx.MockTransport(transport_handler),
    )
    adapter = ServiceNowAdapter(client=client)
    await adapter.connect(_make_source(table))
    try:
        return await adapter.execute(intent=_intent(), scope=scope, context={})
    finally:
        await adapter.close()


# ---------------------------------------------------------------------------
# Happy path: sys_id-pinned sys_attachment query gains content_b64
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_pinned_attachment_row_gains_content_b64() -> None:
    handler = _SnTransport([_meta_row()])
    result = await _run(handler, _pin())

    assert len(result.rows) == 1
    row = result.rows[0]
    assert row["content_b64"] == base64.b64encode(_DOCX_BYTES).decode("ascii")
    assert "content_error" not in row
    assert handler.binary_paths == [f"/api/now/attachment/{_SYS_ID}/file"]


@pytest.mark.unit
async def test_in_pinned_rows_each_gain_content() -> None:
    handler = _SnTransport([_meta_row(_SYS_ID), _meta_row(_SYS_ID_2)])
    scope = [
        ScopeConstraint(
            source_id="sn_attach",
            field="sys_id",
            operator="IN",
            value=[_SYS_ID, _SYS_ID_2],
        )
    ]
    result = await _run(handler, scope)

    assert [r["content_b64"] for r in result.rows] == [
        base64.b64encode(_DOCX_BYTES).decode("ascii")
    ] * 2
    assert sorted(handler.binary_paths) == [
        f"/api/now/attachment/{_SYS_ID}/file",
        f"/api/now/attachment/{_SYS_ID_2}/file",
    ]


# ---------------------------------------------------------------------------
# No pin / wrong table → metadata-only, zero binary requests
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_unpinned_attachment_query_stays_metadata_only() -> None:
    handler = _SnTransport([_meta_row()])
    scope = [
        ScopeConstraint(source_id="sn_attach", field="file_name", operator="LIKE", value="doc")
    ]
    result = await _run(handler, scope)

    assert "content_b64" not in result.rows[0]
    assert handler.binary_paths == []


@pytest.mark.unit
async def test_non_attachment_table_untouched_by_sys_id_pin() -> None:
    handler = _SnTransport([{"sys_id": _SYS_ID, "name": "Doc"}])
    result = await _run(handler, _pin(), table="x_krn_document_doc")

    assert "content_b64" not in result.rows[0]
    assert handler.binary_paths == []


# ---------------------------------------------------------------------------
# Size caps: metadata pre-check + post-download length check
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_oversize_metadata_skips_download(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sn_mod, "_MAX_ATTACHMENT_BYTES", 16)
    handler = _SnTransport([_meta_row(size="17")])
    result = await _run(handler, _pin())

    row = result.rows[0]
    assert row["content_error"] == "attachment-too-large"
    assert "content_b64" not in row
    assert handler.binary_paths == []  # never even requested


@pytest.mark.unit
async def test_oversize_body_rejected_post_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Metadata lies small, body is actually over the cap → still rejected.
    monkeypatch.setattr(sn_mod, "_MAX_ATTACHMENT_BYTES", 4)
    handler = _SnTransport([_meta_row(size="2")], file_bytes=b"12345")
    result = await _run(handler, _pin())

    row = result.rows[0]
    assert row["content_error"] == "attachment-too-large"
    assert "content_b64" not in row


# ---------------------------------------------------------------------------
# Row-count cap → loud AdapterError
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_row_count_over_cap_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sn_mod, "_MAX_ATTACHMENT_FETCHES", 2)
    handler = _SnTransport([_meta_row(_SYS_ID), _meta_row(_SYS_ID_2), _meta_row(_SYS_ID_3)])
    scope = [
        ScopeConstraint(
            source_id="sn_attach",
            field="sys_id",
            operator="IN",
            value=[_SYS_ID, _SYS_ID_2, _SYS_ID_3],
        )
    ]
    with pytest.raises(AdapterError, match="sn-attachment-fetch-cap"):
        await _run(handler, scope)
    assert handler.binary_paths == []  # cap enforced before any download


# ---------------------------------------------------------------------------
# Hostile sys_id in the response row never reaches the request path
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_malformed_sys_id_marked_not_requested() -> None:
    handler = _SnTransport([_meta_row(sys_id="../../evil")])
    result = await _run(handler, _pin())

    row = result.rows[0]
    assert row["content_error"] == "sn-invalid-sys-id"
    assert "content_b64" not in row
    assert handler.binary_paths == []
