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
from collections.abc import Collection
from typing import Any, ClassVar, cast
from urllib.parse import parse_qs, urlsplit, urlunsplit

from nautilus.adapters.base import AdapterError, ScopeEnforcementError, wrap_execute
from nautilus.adapters.schema import AdapterSchema
from nautilus.config.models import BasicAuth, NoneAuth, SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# Default row cap when the intent does not specify a ``LIMIT``.
_DEFAULT_LIMIT: int = 1000


def _client_kwargs(config: SourceConfig) -> dict[str, Any]:
    """Build the aiobotocore ``create_client`` kwargs for one source.

    ``SourceConfig.connection`` is a post-interpolation *string*, always. Two
    shapes are accepted:

    - ``s3://[REGION]`` — real AWS; the optional host is the region name.
    - ``http(s)://HOST[:PORT]`` — an S3-compatible endpoint (MinIO, Ceph, R2).

    Either accepts ``?region=NAME``. When no region is given none is passed,
    which leaves ``AWS_REGION`` / ``AWS_DEFAULT_REGION`` / ``~/.aws/config`` in
    charge; the previous unconditional ``us-east-1`` overrode all three and made
    every bucket outside that region unreachable.

    Credentials come from ``auth:`` like every other adapter — ``basic`` maps
    to (access key, secret key). The old ``access_key:`` / ``secret_key:``
    sibling keys never worked: ``SourceConfig`` ignores unknown fields, so they
    were dropped in silence.
    """
    split = urlsplit(config.connection)
    region = (parse_qs(split.query).get("region") or [""])[0]
    kwargs: dict[str, Any] = {}
    if split.scheme == "s3":
        region = region or split.netloc
    else:
        # Strip the query: it is Nautilus configuration, and a query string on
        # an endpoint URL breaks SigV4 signing.
        kwargs["endpoint_url"] = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
    if region:
        kwargs["region_name"] = region

    auth = config.auth
    if isinstance(auth, BasicAuth):
        kwargs["aws_access_key_id"] = auth.username
        kwargs["aws_secret_access_key"] = auth.password
    elif auth is not None and not isinstance(auth, NoneAuth):
        raise AdapterError(
            f"S3Adapter: source '{config.id}' declares auth type {auth.type!r}, which S3 "
            f"cannot use. Use 'basic' (username=access key id, password=secret access "
            f"key), or omit 'auth' to use the ambient credential chain."
        )
    return kwargs


# One parsed tag predicate: (tag_name, operator, operand). The operand is a
# tuple of members for ``IN`` and a single string otherwise.
_TagFilter = tuple[str, str, "str | tuple[str, ...]"]


def _tag_operand(op: str, value: Any) -> str | tuple[str, ...]:
    """Coerce a scope value into the operand ``_matches_tags`` compares against.

    ``IN`` keeps its members separate so membership stays exact. A bare
    string is one member, not a sequence of characters.
    """
    if op != "IN":
        return str(value)
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set, frozenset)):
        members = cast("Collection[object]", value)
        return tuple(str(v) for v in members)
    raise ScopeEnforcementError(
        f"S3Adapter: IN operator requires a list value, got {type(value).__name__}"
    )


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

        ``connection`` is either ``s3://[REGION]`` (real AWS) or the URL of an
        S3-compatible endpoint; ``table`` is the bucket. See
        :func:`_client_kwargs` for the region and credential rules.
        """
        from aiobotocore.session import AioSession  # pyright: ignore[reportMissingTypeStubs]

        self._config = config
        self._bucket = config.table or "default"
        self._session = AioSession()
        client_kwargs = _client_kwargs(config)
        if "endpoint_url" in client_kwargs and not (
            "region_name" in client_kwargs or self._session.get_config_variable("region")
        ):
            # SigV4 needs *a* region even against MinIO/Ceph, which ignore it.
            # Only filled in when the ambient chain has none, so AWS_REGION and
            # ~/.aws/config still win (R2, for one, insists on "auto").
            client_kwargs["region_name"] = "us-east-1"

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

    @wrap_execute
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

        # Every constraint on a field ANDs with the others. These used to be
        # single slots assigned in the loop, so a second constraint on 'key'
        # overwrote the first: "under restricted/ AND not the payroll object"
        # returned the payroll object.
        prefixes: list[str] = []
        exact_keys: set[str] = set()
        classifications: set[str] = set()
        # (tag_name, op, value). ``IN`` keeps its members as a tuple; it used
        # to be str(value), which turned ["alice", "bob"] into the literal
        # "['alice', 'bob']" and made the membership test below a substring
        # match -- a tag value of "li" passed a filter for alice-or-bob.
        tag_filters: list[_TagFilter] = []

        for constraint in scope:
            field = constraint.field
            op = constraint.operator
            value: Any = constraint.value

            if field == "key":
                if op == "=":
                    exact_keys.add(str(value))
                elif op == "LIKE":
                    if not isinstance(value, str):
                        raise ScopeEnforcementError(
                            "S3Adapter: LIKE operator requires a string value"
                        )
                    # Strip trailing % wildcard for prefix matching.
                    prefixes.append(value.rstrip("%"))
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
                tag_filters.append((tag_name, op, _tag_operand(op, value)))
            elif field == "classification":
                if op != "=":
                    raise ScopeEnforcementError(
                        f"S3Adapter: unsupported operator '{op}' for classification"
                    )
                classifications.add(str(value))
            else:
                raise ScopeEnforcementError(f"S3Adapter: unsupported scope field '{field}'")

        # Intersect the accumulated constraints. The longest prefix is the
        # binding one; anything the others exclude makes the whole conjunction
        # unsatisfiable, and so does a second, different exact key or
        # classification. An unsatisfiable scope selects no object -- returning
        # rows for the loosest of the constraints would be the fail-open.
        prefix: str | None = max(prefixes, key=len) if prefixes else None
        exact_key: str | None = next(iter(exact_keys)) if len(exact_keys) == 1 else None
        unsatisfiable = (
            len(exact_keys) > 1
            or len(classifications) > 1
            or (prefix is not None and any(not prefix.startswith(p) for p in prefixes))
            or (exact_key is not None and prefix is not None and not exact_key.startswith(prefix))
            # Classification gate: the source's own label must match the
            # requested one.
            or bool(classifications and self._config.classification not in classifications)
        )
        if unsatisfiable:
            return AdapterResult(
                source_id=self._config.id,
                rows=[],
                duration_ms=0,
            )

        started = time.perf_counter()

        try:
            if exact_key is not None:
                # AND with the other constraints. Short-circuiting straight to
                # the object dropped ``prefix`` and ``tag_filters`` -- both
                # already parsed -- while they stayed in
                # ``BrokerResponse.scope_restrictions`` and in the signed
                # attestation as though applied. Every other adapter ANDs.
                matches = (not prefix or exact_key.startswith(prefix)) and (
                    not tag_filters or await self._matches_tags(exact_key, tag_filters)
                )
                rows = await self._get_object(exact_key) if matches else []
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
            truncated=len(rows) >= _DEFAULT_LIMIT,
        )

    async def get_schema(self) -> AdapterSchema:
        """S3 has no introspectable schema — return capability_only. AC-21, OQ3."""
        adapter_id = self._config.id if self._config else "s3"
        return AdapterSchema.unknown(adapter_id, self.source_type)

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
        tag_filters: list[_TagFilter],
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
        tag_filters: list[_TagFilter],
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
                # ``expected`` is a tuple of members here, so this is exact
                # membership rather than a substring test.
                return False

        return True


__all__ = ["S3Adapter"]
