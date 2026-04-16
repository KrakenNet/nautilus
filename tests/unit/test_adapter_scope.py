"""Unit tests for InfluxDB and S3 scope-to-query mapping (Task 3.6).

Tests scope constraint translation without real InfluxDB or S3 connections:

a) InfluxDB: ScopeConstraint → Flux filter fragments (=, !=, <, >, <=, >=,
   IN, NOT IN, LIKE, BETWEEN, IS NULL, _time range).
b) S3: ScopeConstraint → prefix, tag, classification filters.
c) Scope validation: invalid operators and field names are rejected.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from nautilus.adapters.base import ScopeEnforcementError
from nautilus.adapters.influxdb import InfluxDBAdapter, _flux_escape
from nautilus.adapters.s3 import S3Adapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import ScopeConstraint

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _influx_adapter() -> InfluxDBAdapter:
    """Return an InfluxDBAdapter with a mock client (no real connection)."""
    adapter = InfluxDBAdapter(client=AsyncMock())
    adapter._config = SourceConfig(  # pyright: ignore[reportPrivateUsage]
        id="metrics",
        type="postgres",  # type irrelevant for scope-mapping tests
        description="time-series metrics",
        classification="internal",
        data_types=["metric"],
        allowed_purposes=["monitoring"],
        connection="http://localhost:8086",
        table="my_bucket",
    )
    return adapter


def _build_flux(
    scope: list[ScopeConstraint],
    bucket: str = "test_bucket",
    limit: int = 100,
) -> str:
    """Call ``_build_flux`` directly on a fresh adapter."""
    adapter = _influx_adapter()
    return adapter._build_flux(bucket, scope, limit)  # pyright: ignore[reportPrivateUsage]


def _sc(
    field: str,
    operator: str,
    value: object = None,
    source_id: str = "src",
) -> ScopeConstraint:
    """Shorthand ScopeConstraint factory."""
    return ScopeConstraint(
        source_id=source_id,
        field=field,
        operator=operator,  # type: ignore[arg-type]
        value=value,
    )


# ===================================================================
# InfluxDB scope mapping
# ===================================================================


class TestInfluxDBScopeMapping:
    """ScopeConstraint → Flux filter fragment tests."""

    def test_equals_operator(self) -> None:
        flux = _build_flux([_sc("host", "=", "web-1")])
        assert 'r["host"] == "web-1"' in flux

    def test_not_equals_operator(self) -> None:
        flux = _build_flux([_sc("host", "!=", "web-1")])
        assert 'r["host"] != "web-1"' in flux

    def test_less_than_operator(self) -> None:
        flux = _build_flux([_sc("cpu", "<", 90)])
        assert 'r["cpu"] < 90' in flux

    def test_greater_than_operator(self) -> None:
        flux = _build_flux([_sc("cpu", ">", 50)])
        assert 'r["cpu"] > 50' in flux

    def test_less_than_or_equal_operator(self) -> None:
        flux = _build_flux([_sc("cpu", "<=", 80)])
        assert 'r["cpu"] <= 80' in flux

    def test_greater_than_or_equal_operator(self) -> None:
        flux = _build_flux([_sc("cpu", ">=", 10)])
        assert 'r["cpu"] >= 10' in flux

    def test_in_operator(self) -> None:
        flux = _build_flux([_sc("region", "IN", ["us-east", "eu-west"])])
        assert 'r["region"] == "us-east" or r["region"] == "eu-west"' in flux

    def test_not_in_operator(self) -> None:
        flux = _build_flux([_sc("region", "NOT IN", ["cn-north"])])
        assert 'r["region"] != "cn-north"' in flux

    def test_like_operator(self) -> None:
        flux = _build_flux([_sc("host", "LIKE", "%web%")])
        assert "strings.containsStr" in flux
        assert 'substr: "web"' in flux

    def test_between_operator(self) -> None:
        flux = _build_flux([_sc("cpu", "BETWEEN", [10, 90])])
        assert 'r["cpu"] >= 10 and r["cpu"] <= 90' in flux

    def test_is_null_operator(self) -> None:
        flux = _build_flux([_sc("host", "IS NULL")])
        assert 'not exists r["host"]' in flux

    def test_time_range_via_scope(self) -> None:
        flux = _build_flux([
            _sc("_time", ">=", "2024-01-01T00:00:00Z"),
            _sc("_time", "<=", "2024-01-31T23:59:59Z"),
        ])
        assert "2024-01-01T00:00:00Z" in flux
        assert "2024-01-31T23:59:59Z" in flux
        assert "range(start:" in flux.replace(" ", "")

    def test_time_between(self) -> None:
        flux = _build_flux([
            _sc("_time", "BETWEEN", ["2024-01-01", "2024-01-31"]),
        ])
        assert '"2024-01-01"' in flux
        assert '"2024-01-31"' in flux

    def test_multiple_constraints_produce_chained_filters(self) -> None:
        flux = _build_flux([
            _sc("host", "=", "web-1"),
            _sc("_measurement", "=", "cpu"),
        ])
        # Each constraint should produce its own |> filter(...) line.
        assert flux.count("|> filter(") == 2

    def test_bucket_and_limit_in_output(self) -> None:
        flux = _build_flux([_sc("host", "=", "a")], bucket="my_bucket", limit=42)
        assert 'from(bucket: "my_bucket")' in flux
        assert "|> limit(n: 42)" in flux

    def test_in_operator_requires_list(self) -> None:
        with pytest.raises(ScopeEnforcementError, match="list value"):
            _build_flux([_sc("region", "IN", "not-a-list")])

    def test_not_in_operator_requires_list(self) -> None:
        with pytest.raises(ScopeEnforcementError, match="list value"):
            _build_flux([_sc("region", "NOT IN", "not-a-list")])

    def test_between_requires_two_element_sequence(self) -> None:
        with pytest.raises(ScopeEnforcementError, match="2-tuple"):
            _build_flux([_sc("cpu", "BETWEEN", [1])])

    def test_time_between_requires_two_element_sequence(self) -> None:
        with pytest.raises(ScopeEnforcementError, match="2-tuple"):
            _build_flux([_sc("_time", "BETWEEN", [1])])

    def test_like_requires_string(self) -> None:
        with pytest.raises(ScopeEnforcementError, match="string value"):
            _build_flux([_sc("host", "LIKE", 123)])


class TestFluxEscape:
    """Verify ``_flux_escape`` handles types correctly."""

    def test_string_value(self) -> None:
        assert _flux_escape("hello") == '"hello"'

    def test_string_with_quotes(self) -> None:
        assert _flux_escape('say "hi"') == '"say \\"hi\\""'

    def test_int_value(self) -> None:
        assert _flux_escape(42) == "42"

    def test_float_value(self) -> None:
        assert _flux_escape(3.14) == "3.14"

    def test_bool_true(self) -> None:
        assert _flux_escape(True) == "true"

    def test_bool_false(self) -> None:
        assert _flux_escape(False) == "false"


# ===================================================================
# S3 scope mapping
# ===================================================================


class TestS3ScopeMapping:
    """ScopeConstraint → S3 prefix / tag / classification filter tests.

    These tests exercise the scope-parsing logic in ``S3Adapter.execute``
    via direct invocation with mocked boto client.
    """

    @pytest.fixture()
    def adapter(self) -> S3Adapter:
        """Create an S3Adapter with mocked internals."""
        a = S3Adapter()
        a._config = SourceConfig(  # pyright: ignore[reportPrivateUsage]
            id="docs",
            type="postgres",  # type irrelevant for scope-mapping tests
            description="document store",
            classification="confidential",
            data_types=["document"],
            allowed_purposes=["research"],
            connection="http://localhost:9000",
        )
        a._bucket = "test-bucket"  # pyright: ignore[reportPrivateUsage]
        mock_client = AsyncMock()
        # Default: list returns empty, get_object returns body.
        mock_client.list_objects_v2.return_value = {"Contents": []}
        mock_client.get_object.return_value = {
            "Body": AsyncMock(read=AsyncMock(return_value=b"data")),
            "ContentLength": 4,
            "ContentType": "text/plain",
            "LastModified": "2024-01-01",
        }
        a._client = mock_client  # pyright: ignore[reportPrivateUsage]
        return a

    @pytest.mark.asyncio
    async def test_key_equals_fetches_exact_object(self, adapter: S3Adapter) -> None:
        scope = [_sc("key", "=", "path/to/file.txt", source_id="docs")]
        await adapter.execute(
            intent=AsyncMock(),
            scope=scope,
            context={},
        )
        adapter._client.get_object.assert_called_once()  # pyright: ignore[reportPrivateUsage]
        call_kwargs = adapter._client.get_object.call_args.kwargs  # pyright: ignore[reportPrivateUsage]
        assert call_kwargs["Key"] == "path/to/file.txt"

    @pytest.mark.asyncio
    async def test_key_like_sets_prefix(self, adapter: S3Adapter) -> None:
        scope = [_sc("key", "LIKE", "reports/%", source_id="docs")]
        await adapter.execute(intent=AsyncMock(), scope=scope, context={})
        adapter._client.list_objects_v2.assert_called_once()  # pyright: ignore[reportPrivateUsage]
        call_kwargs = adapter._client.list_objects_v2.call_args.kwargs  # pyright: ignore[reportPrivateUsage]
        assert call_kwargs["Prefix"] == "reports/"

    @pytest.mark.asyncio
    async def test_tag_filter_equals(self, adapter: S3Adapter) -> None:
        # Set up list to return one object so tag filtering runs.
        adapter._client.list_objects_v2.return_value = {  # pyright: ignore[reportPrivateUsage]
            "Contents": [{"Key": "a.txt", "Size": 10, "LastModified": "2024-01-01"}],
        }
        adapter._client.get_object_tagging.return_value = {  # pyright: ignore[reportPrivateUsage]
            "TagSet": [{"Key": "dept", "Value": "finance"}],
        }
        scope = [_sc("tag.dept", "=", "finance", source_id="docs")]
        result = await adapter.execute(intent=AsyncMock(), scope=scope, context={})
        assert len(result.rows) == 1

    @pytest.mark.asyncio
    async def test_tag_filter_not_equals(self, adapter: S3Adapter) -> None:
        adapter._client.list_objects_v2.return_value = {  # pyright: ignore[reportPrivateUsage]
            "Contents": [{"Key": "a.txt", "Size": 10, "LastModified": "2024-01-01"}],
        }
        adapter._client.get_object_tagging.return_value = {  # pyright: ignore[reportPrivateUsage]
            "TagSet": [{"Key": "dept", "Value": "finance"}],
        }
        scope = [_sc("tag.dept", "!=", "engineering", source_id="docs")]
        result = await adapter.execute(intent=AsyncMock(), scope=scope, context={})
        assert len(result.rows) == 1

    @pytest.mark.asyncio
    async def test_tag_filter_rejects_mismatch(self, adapter: S3Adapter) -> None:
        adapter._client.list_objects_v2.return_value = {  # pyright: ignore[reportPrivateUsage]
            "Contents": [{"Key": "a.txt", "Size": 10, "LastModified": "2024-01-01"}],
        }
        adapter._client.get_object_tagging.return_value = {  # pyright: ignore[reportPrivateUsage]
            "TagSet": [{"Key": "dept", "Value": "finance"}],
        }
        scope = [_sc("tag.dept", "=", "engineering", source_id="docs")]
        result = await adapter.execute(intent=AsyncMock(), scope=scope, context={})
        assert len(result.rows) == 0

    @pytest.mark.asyncio
    async def test_classification_filter_matches(self, adapter: S3Adapter) -> None:
        scope = [_sc("classification", "=", "confidential", source_id="docs")]
        await adapter.execute(intent=AsyncMock(), scope=scope, context={})
        # Classification matches config — should proceed to list/get.
        adapter._client.list_objects_v2.assert_called_once()  # pyright: ignore[reportPrivateUsage]

    @pytest.mark.asyncio
    async def test_classification_filter_mismatch_returns_empty(
        self, adapter: S3Adapter
    ) -> None:
        scope = [_sc("classification", "=", "top-secret", source_id="docs")]
        result = await adapter.execute(intent=AsyncMock(), scope=scope, context={})
        assert result.rows == []
        assert result.duration_ms == 0

    @pytest.mark.asyncio
    async def test_unsupported_key_operator_raises(self, adapter: S3Adapter) -> None:
        scope = [_sc("key", ">", "abc", source_id="docs")]
        with pytest.raises(ScopeEnforcementError, match="unsupported operator"):
            await adapter.execute(intent=AsyncMock(), scope=scope, context={})

    @pytest.mark.asyncio
    async def test_unsupported_field_raises(self, adapter: S3Adapter) -> None:
        scope = [_sc("unknown_field", "=", "val", source_id="docs")]
        with pytest.raises(ScopeEnforcementError, match="unsupported scope field"):
            await adapter.execute(intent=AsyncMock(), scope=scope, context={})

    @pytest.mark.asyncio
    async def test_classification_unsupported_operator_raises(
        self, adapter: S3Adapter
    ) -> None:
        scope = [_sc("classification", "!=", "secret", source_id="docs")]
        with pytest.raises(ScopeEnforcementError, match="unsupported operator"):
            await adapter.execute(intent=AsyncMock(), scope=scope, context={})

    @pytest.mark.asyncio
    async def test_tag_unsupported_operator_raises(self, adapter: S3Adapter) -> None:
        scope = [_sc("tag.dept", "LIKE", "fin%", source_id="docs")]
        with pytest.raises(ScopeEnforcementError, match="unsupported operator"):
            await adapter.execute(intent=AsyncMock(), scope=scope, context={})

    @pytest.mark.asyncio
    async def test_empty_tag_name_raises(self, adapter: S3Adapter) -> None:
        scope = [_sc("tag.", "=", "val", source_id="docs")]
        with pytest.raises(ScopeEnforcementError, match="empty tag name"):
            await adapter.execute(intent=AsyncMock(), scope=scope, context={})

    @pytest.mark.asyncio
    async def test_key_like_requires_string(self, adapter: S3Adapter) -> None:
        scope = [_sc("key", "LIKE", 123, source_id="docs")]
        with pytest.raises(ScopeEnforcementError, match="string value"):
            await adapter.execute(intent=AsyncMock(), scope=scope, context={})


# ===================================================================
# Scope validation (shared — operators / fields)
# ===================================================================


class TestScopeValidation:
    """Invalid operator and field validation in InfluxDB adapter."""

    def test_invalid_operator_raises(self) -> None:
        # Bypass Pydantic Literal validation to exercise the runtime validator.
        bad = _sc("host", "=", "x")
        bad.__dict__["operator"] = "INVALID_OP"
        with pytest.raises(ScopeEnforcementError, match="not in allowlist"):
            _build_flux([bad])

    def test_invalid_field_raises(self) -> None:
        with pytest.raises(ScopeEnforcementError, match="Invalid field"):
            _build_flux([_sc("1bad_field", "=", "x")])

    def test_injection_field_raises(self) -> None:
        with pytest.raises(ScopeEnforcementError, match="Invalid field"):
            _build_flux([_sc('x"; DROP TABLE', "=", "x")])
