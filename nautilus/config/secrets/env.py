"""``env://VAR`` secret provider — reads ``os.environ[VAR]``."""

from __future__ import annotations

import os
from typing import ClassVar

from . import register


@register("env")
class EnvProvider:
    """Resolve ``env://VAR`` references against ``os.environ``."""

    scheme: ClassVar[str] = "env"

    async def get(self, ref: str) -> str:
        if not ref.startswith("env://"):
            raise ValueError("EnvProvider received non-env ref")
        var = ref.removeprefix("env://")
        if not var:
            raise ValueError("env:// missing variable name")
        value = os.environ.get(var)
        if value is None:
            # Do NOT embed the full ref (NFR-SEC-SECRETS); var name is sufficient.
            raise ValueError(f"environment variable not set: {var!r}")
        return value
