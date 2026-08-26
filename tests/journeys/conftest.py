"""Journey fixtures: the live backends from :mod:`tests.backends`.

The fixtures live in a plain module rather than in this conftest so that
``tests/defects`` can import the same ones. ``pytest_plugins`` is only honoured
in the root conftest, and putting container fixtures at the root would make the
whole suite look as though it needs Docker.
"""

from tests.backends import (  # noqa: F401
    es_url,
    influx,
    minio_endpoint,
    neo4j_bolt,
    pg_dsn,
    write_config,
)
