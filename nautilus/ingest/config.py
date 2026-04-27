"""Per-source ingest-integrity config (US-4, design §"In-memory pydantic schemas").

Mirrors design lines 394-400 verbatim and adds ``baseline_retention`` per OQ-3
resolution (default ``"90d"``; ops prunes out-of-band — no in-broker auto-prune).

The ``schema`` field accepts one of:

* a filesystem path (``/etc/nautilus/schemas/nautobot.json``),
* a registered secret reference (``vault://...``, ``env://VAR``), or
* a ``${VAR}``-interpolated string resolved at config-load time.

Resolution to the on-disk JSON-Schema document happens at
``adapter.connect()`` via :func:`nautilus.config.secrets.resolve` (Task 4's
registry); this model deliberately stores the raw reference so the
round-trip test pins the config contract independent of secret providers.

``baseline_window`` is a ``humanfriendly``-style duration string (``"7d"``,
``"24h"``, ``"30m"``). Parsing is a consumer concern
(:class:`~nautilus.ingest.baseline.BaselineTracker`, Task 27); the model
itself treats it as an opaque ``str`` so YAML round-trips byte-identically
and malformed durations surface as structured errors at the consumer site.

``corroboration_callback`` is the user-supplied post-validation hook
(design §"Ingest Integrity" flow line 755). It is wired at runtime and
never serialised, so it is excluded from ``model_dump`` via pydantic's
standard ``arbitrary_types_allowed`` + ``exclude``-on-dump pattern.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class IngestIntegrityConfig(BaseModel):
    """Per-source ingest-integrity knobs (design lines 394-400 + OQ-3 ``baseline_retention``).

    Attached to :class:`~nautilus.config.models.SourceConfig.ingest_integrity`
    as ``IngestIntegrityConfig | None``. ``None`` disables all ingest-integrity
    behaviour for that source (NFR-BC: pre-existing YAML with no
    ``ingest_integrity`` key continues to load unchanged).
    """

    # ``schema`` is a reserved attribute name on :class:`pydantic.BaseModel`
    # (it's the deprecated JSON-Schema accessor), so the Python attribute is
    # ``schema_`` with an alias so YAML/JSON still use ``schema`` verbatim.
    # ``populate_by_name=True`` lets direct ``IngestIntegrityConfig(schema_=...)``
    # construction work alongside ``model_validate({"schema": ...})``.
    # ``arbitrary_types_allowed=True`` admits the ``Callable`` default.
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        populate_by_name=True,
    )

    schema_: str = Field(alias="schema")
    """Schema reference — filesystem path, ``vault://...``, ``env://VAR``, or ``${VAR}``."""

    on_schema_violation: Literal["quarantine", "reject", "pass-through"] = "quarantine"
    """AC-4.2: what to do when a row fails JSON-schema validation."""

    baseline_window: str = "7d"
    """Rolling-window duration for :class:`BaselineTracker` (humanfriendly-style)."""

    anomaly_sigma: float = 3.0
    """|z|-threshold above which a row is flagged as anomalous (AC-4.9)."""

    on_publisher_schema_change: Literal["pause", "warn"] = "pause"
    """AC-4.3: pause the source or emit a warn-only audit on upstream schema drift."""

    corroboration_callback: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None = Field(
        default=None,
        exclude=True,
    )
    """Optional user hook applied to validated rows (design line 755)."""

    baseline_retention: str = "90d"
    """OQ-3: rolling retention window. Ops prunes out-of-band; no in-broker auto-prune."""
