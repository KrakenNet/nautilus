"""Adapter SDK configuration models.

Provides Pydantic models for declaring and validating adapter source
configurations.  ``SourceConfig`` uses ``extra="allow"`` so operators
can pass adapter-specific keys without schema changes.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class SourceConfig(BaseModel):
    """Configuration for a single data-source adapter instance.

    Operators define one ``SourceConfig`` per source in their deployment
    manifest.  The ``extra="allow"`` policy lets adapter authors accept
    custom keys (e.g., ``database``, ``collection``) without subclassing.
    """

    model_config = ConfigDict(extra="allow")

    id: str
    type: str
    description: str = ""
    classification: str = ""
    data_types: list[str] = []
    allowed_purposes: list[str] = []
    connection: dict[str, Any] = {}
