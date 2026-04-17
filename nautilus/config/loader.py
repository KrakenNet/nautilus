"""YAML config loader with ${VAR} environment interpolation.

Implements FR-1, FR-2 (design §4.1, §4.10).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, cast

import yaml

from nautilus.config.models import NautilusConfig

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
# Phase-2 adds 4 new adapter kinds (design §3.5); unknown kinds still raise
# ``ConfigError`` via the pre-validation check below.
_SUPPORTED_TYPES = {
    "postgres",
    "pgvector",
    "elasticsearch",
    "rest",
    "neo4j",
    "servicenow",
    "influxdb",
    "s3",
}


class ConfigError(Exception):
    """Raised for any config loading or validation failure."""


class EnvInterpolator:
    """Recursively replaces ``${VAR}`` patterns in string fields of a nested dict/list structure.

    Tracks the current source ``id`` so missing-env errors can cite it per FR-2.
    """

    def __init__(self, env: dict[str, str] | None = None) -> None:
        self._env = env if env is not None else dict(os.environ)

    def interpolate(self, data: object) -> object:
        """Walk ``data`` and replace every ``${VAR}`` substring in leaf strings.

        Args:
            data: Arbitrarily nested ``dict``/``list``/``str`` structure
                parsed from YAML.

        Returns:
            A new structure with ``${VAR}`` patterns substituted from the
            interpolator's environment mapping.

        Raises:
            ConfigError: If a referenced environment variable is absent;
                the error message cites the enclosing source ``id`` for
                fast triage (FR-2).
        """
        return self._walk(data, source_id=None)

    def _walk(self, node: object, source_id: str | None) -> object:
        if isinstance(node, dict):
            node_dict = cast(dict[object, object], node)
            # If this dict has a string "id" key (i.e. it's a source entry),
            # pick it up for error context.
            next_source_id = source_id
            raw_id = node_dict.get("id")
            if isinstance(raw_id, str):
                next_source_id = raw_id
            return {k: self._walk(v, next_source_id) for k, v in node_dict.items()}
        if isinstance(node, list):
            node_list = cast(list[object], node)
            return [self._walk(item, source_id) for item in node_list]
        if isinstance(node, str):
            return self._interpolate_str(node, source_id)
        return node

    def _interpolate_str(self, value: str, source_id: str | None) -> str:
        def _sub(match: re.Match[str]) -> str:
            var = match.group(1)
            if var not in self._env:
                raise ConfigError(f"Missing env var '{var}' referenced by source id='{source_id}'")
            return self._env[var]

        return _ENV_PATTERN.sub(_sub, value)


def load_config(path: str | Path) -> NautilusConfig:
    """Load, interpolate, validate, and return a :class:`NautilusConfig`.

    Raises :class:`ConfigError` on missing env vars, duplicate source ids,
    unsupported source types, or Pydantic validation failures.
    """
    config_path = Path(path)
    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Unable to read config file '{config_path}': {exc}") from exc

    try:
        raw: object = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in '{config_path}': {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"Config root must be a mapping, got {type(raw).__name__}")
    raw_dict: dict[object, object] = cast(dict[object, object], raw)

    interpolated = EnvInterpolator().interpolate(raw_dict)
    if not isinstance(interpolated, dict):
        raise ConfigError("Interpolated config root must remain a mapping")
    interpolated_dict = cast(dict[str, Any], interpolated)

    sources_raw = interpolated_dict.get("sources")
    if not isinstance(sources_raw, list):
        raise ConfigError("Config must define a 'sources' list")
    sources_list = cast(list[object], sources_raw)

    seen_ids: set[str] = set()
    for entry in sources_list:
        if not isinstance(entry, dict):
            raise ConfigError("Each source entry must be a mapping")
        entry_dict = cast(dict[str, object], entry)
        source_id = entry_dict.get("id")
        if not isinstance(source_id, str):
            raise ConfigError("Each source entry must have a string 'id'")
        if source_id in seen_ids:
            raise ConfigError(f"Duplicate source id='{source_id}'")
        seen_ids.add(source_id)

        source_type = entry_dict.get("type")
        if source_type not in _SUPPORTED_TYPES:
            raise ConfigError(
                f"Unsupported source type='{source_type}' for id='{source_id}' "
                f"(supported: {sorted(_SUPPORTED_TYPES)})"
            )

    try:
        return NautilusConfig.model_validate(interpolated_dict)
    except Exception as exc:
        raise ConfigError(f"Config validation failed: {exc}") from exc
