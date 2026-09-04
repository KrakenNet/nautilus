"""Defect-pin fixtures: the same live backends the journeys use.

A pin that runs against a mock proves nothing. Every defect in REPORT.md
survived a 1533-test suite, largely because that suite mocked the backend the
defect lives in.
"""

from tests.backends import (  # noqa: F401
    es_url,
    influx,
    minio_endpoint,
    neo4j_bolt,
    pg_dsn,
    write_config,
)

# Named here as well as imported: an import that only exists so pytest can
# discover the fixture reads as unused to a type checker, and ``__all__`` is
# how a module says a name is deliberately re-exported.
__all__ = [
    "es_url",
    "influx",
    "minio_endpoint",
    "neo4j_bolt",
    "pg_dsn",
    "write_config",
]
