"""S3 adapter using ``aiobotocore`` with prefix/tag/classification scoping.

Implements the ``Adapter`` protocol (design §3.5) for S3-compatible object
stores (AWS S3, MinIO, Ceph, Cloudflare R2). Scope constraints are mapped to:

- **prefix**: ``field="key"`` constraints restrict ``ListObjectsV2`` prefix.
- **tag filtering**: ``field="tag.<name>"`` constraints filter objects by S3
  object tagging after listing.
- **classification**: ``field="classification"`` constraints match against the
  source's ``SourceConfig.classification`` label.

The adapter uses ``aiobotocore`` sessions so it participates in the standard
asyncio event loop without blocking.
"""

from __future__ import annotations

import contextlib
import time
from typing import Any, ClassVar

from nautilus.adapters.base import AdapterError, ScopeEnforcementError
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# Default row cap when the intent does not specify a ``LIMIT``.
_DEFAULT_LIMIT: int = 1000


class S3Adapter:
    """S3-compatible object-store adapter backed by ``aiobotocore``.

    Construction is cheap; the actual session and client are built in
    :meth:`connect` so failures bubble up through the broker's
    ``sources_errored`` path (design §3.5 / FR-18).
    """

    source_type: ClassVar[str] = "s3"

    def __init__(self) -> None:
        self._session: Any | None = None
        self._client: Any | None = None
        self._config: SourceConfig | None = None
        self._bucket: str | None = None
        self._closed: bool = False

    async def connect(self, config: SourceConfig) -> None:
        """Create an aiobotocore session and S3 client from ``config``.

        ``config.connection`` is expected to carry a JSON-like or
        semicolon-delimited connection descriptor. For Phase 1, the adapter
        reads well-known keys from the config object:

        - ``endpoint_url``: S3-compatible endpoint (MinIO, Ceph, R2)
        - ``region``: AWS region name (defaults to ``us-east-1``)
        - ``access_key``: AWS access key ID
        - ``secret_key``: AWS secret access key
        - ``bucket``: target bucket name

        These are passed via ``config.connection`` as a Python dict (parsed
        upstream by the config loader) or directly via named config fields.
        """
        from aiobotocore.session import AioSession  # pyright: ignore[reportMissingTypeStubs]

        self._config = config

        # Connection can be a dict-like object or a string DSN. For Phase 1
        # we expect the broker to pass a dict via config.connection; if it is
        # a plain string, treat it as the endpoint URL with env-based auth.
        conn: Any = config.connection
        if isinstance(conn, dict):
            conn_dict: dict[str, Any] = conn  # pyright: ignore[reportUnknownVariableType]
        else:
            # Fallback: treat connection string as endpoint_url, rely on
            # environment variables for auth (standard boto credential chain).
            conn_dict = {"endpoint_url": str(conn)}

        self._bucket = conn_dict.get("bucket") or config.table or "default"

        session_kwargs: dict[str, Any] = {}
        self._session = AioSession(**session_kwargs)

        client_kwargs: dict[str, Any] = {
            "region_name": conn_dict.get("region", "us-east-1"),
        }
        endpoint_url = conn_dict.get("endpoint_url")
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url

        access_key = conn_dict.get("access_key")
        secret_key = conn_dict.get("secret_key")
        if access_key and secret_key:
            client_kwargs["aws_access_key_id"] = access_key
            client_kwargs["aws_secret_access_key"] = secret_key

        try:
            ctx = self._session.create_client("s3", **client_kwargs)
            self._client = await ctx.__aenter__()
            # Stash the context manager so close() can exit cleanly.
            self._client_ctx = ctx
        except Exception as exc:
            raise AdapterError(
                f"S3Adapter failed to create client for source '{config.id}': {exc}"
            ) from exc

    async def close(self) -> None:
        """Release the client. Idempotent — second call is a no-op (FR-17)."""
        if self._closed:
            return
        self._closed = True
        client_ctx = getattr(self, "_client_ctx", None)
        self._client = None
        if client_ctx is not None:
            with contextlib.suppress(Exception):
                await client_ctx.__aexit__(None, None, None)

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """List/get S3 objects matching scope constraints.

        Scope mapping:

        - ``field="key"`` with ``operator="="`` → exact key ``GetObject``
        - ``field="key"`` with ``operator="LIKE"`` → prefix-based
          ``ListObjectsV2`` (``%`` suffix stripped, used as ``Prefix``)
        - ``field="tag.<name>"`` → post-list filter on object tags
        - ``field="classification"`` → matches ``SourceConfig.classification``

        All other scope fields raise ``ScopeEnforcementError``.
        """
        del intent, context  # Phase 1: not consumed by S3 adapter
        if self._client is None or self._config is None or self._bucket is None:
            raise AdapterError("S3Adapter.execute called before connect()")

        prefix: str | None = None
        exact_key: str | None = None
        tag_filters: list[tuple[str, str, str]] = []  # (tag_name, op, value)
        classification_filter: str | None = None

        for constraint in scope:
            field = constraint.field
            op = constraint.operator
            value: Any = constraint.value

            if field == "key":
                if op == "=":
                    exact_key = str(value)
                elif op == "LIKE":
                    if not isinstance(value, str):
                        raise ScopeEnforcementError(
                            "S3Adapter: LIKE operator requires a string value"
                        )
                    # Strip trailing % wildcard for prefix matching.
                    prefix = value.rstrip("%")
                else:
                    raise ScopeEnforcementError(
                        f"S3Adapter: unsupported operator '{op}' for field 'key'"
                    )
            elif field.startswith("tag."):
                tag_name = field[4:]
                if not tag_name:
                    raise ScopeEnforcementError("S3Adapter: empty tag name")
                if op not in ("=", "!=", "IN"):
                    raise ScopeEnforcementError(
                        f"S3Adapter: unsupported operator '{op}' for tag filter"
                    )
                tag_filters.append((tag_name, op, str(value)))
            elif field == "classification":
                if op != "=":
                    raise ScopeEnforcementError(
                        f"S3Adapter: unsupported operator '{op}' for classification"
                    )
                classification_filter = str(value)
            else:
                raise ScopeEnforcementError(f"S3Adapter: unsupported scope field '{field}'")

        # Classification gate: reject early if the source classification
        # does not match the requested classification label.
        if (
            classification_filter is not None
            and self._config.classification != classification_filter
        ):
            return AdapterResult(
                source_id=self._config.id,
                rows=[],
                duration_ms=0,
            )

        started = time.perf_counter()

        try:
            if exact_key is not None:
                rows = await self._get_object(exact_key)
            else:
                rows = await self._list_objects(
                    prefix=prefix,
                    tag_filters=tag_filters,
                    limit=_DEFAULT_LIMIT,
                )
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError(
                f"S3Adapter request failed for source '{self._config.id}': {exc}"
            ) from exc

        duration_ms = int((time.perf_counter() - started) * 1000)
        return AdapterResult(
            source_id=self._config.id,
            rows=rows,
            duration_ms=duration_ms,
        )

    async def _get_object(self, key: str) -> list[dict[str, Any]]:
        """Fetch a single object by exact key and return metadata + body."""
        if self._client is None:
            raise AdapterError("S3Adapter is not connected")
        response = await self._client.get_object(
            Bucket=self._bucket,
            Key=key,
        )
        body_stream = response["Body"]
        body_bytes: bytes = await body_stream.read()
        return [
            {
                "key": key,
                "size": response.get("ContentLength", len(body_bytes)),
                "content_type": response.get("ContentType", "application/octet-stream"),
                "last_modified": str(response.get("LastModified", "")),
                "body": body_bytes.decode("utf-8", errors="replace"),
            }
        ]

    async def _list_objects(
        self,
        prefix: str | None,
        tag_filters: list[tuple[str, str, str]],
        limit: int,
    ) -> list[dict[str, Any]]:
        """List objects with optional prefix, applying tag filters post-list."""
        if self._client is None:
            raise AdapterError("S3Adapter is not connected")
        list_kwargs: dict[str, Any] = {"Bucket": self._bucket, "MaxKeys": limit}
        if prefix:
            list_kwargs["Prefix"] = prefix

        response = await self._client.list_objects_v2(**list_kwargs)
        contents: list[dict[str, Any]] = response.get("Contents", [])
        rows: list[dict[str, Any]] = []

        for obj in contents:
            key: str = obj.get("Key", "")
            row: dict[str, Any] = {
                "key": key,
                "size": obj.get("Size", 0),
                "last_modified": str(obj.get("LastModified", "")),
            }

            # Apply tag filters if any are specified.
            if tag_filters and not await self._matches_tags(key, tag_filters):
                continue

            rows.append(row)
            if len(rows) >= limit:
                break

        return rows

    async def _matches_tags(
        self,
        key: str,
        tag_filters: list[tuple[str, str, str]],
    ) -> bool:
        """Check whether an object's tags satisfy all tag filter constraints."""
        if self._client is None:
            raise AdapterError("S3Adapter is not connected")
        try:
            tag_response = await self._client.get_object_tagging(
                Bucket=self._bucket,
                Key=key,
            )
        except Exception:
            return False

        tag_set: list[dict[str, str]] = tag_response.get("TagSet", [])
        tags: dict[str, str] = {t["Key"]: t["Value"] for t in tag_set}

        for tag_name, op, expected in tag_filters:
            actual = tags.get(tag_name)
            if op == "=":
                if actual != expected:
                    return False
            elif op == "!=":
                if actual == expected:
                    return False
            elif op == "IN" and (actual is None or actual not in expected):
                # Value was stringified from a list; for IN we check membership.
                return False

        return True


__all__ = ["S3Adapter"]
