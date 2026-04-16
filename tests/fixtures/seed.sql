-- Test seed data for integration tests (design §13.3).
-- Requires the `vector` extension (pgvector image provides it).

CREATE EXTENSION IF NOT EXISTS vector;

-- Plain relational table for PostgresAdapter tests.
CREATE TABLE IF NOT EXISTS vulns (
    id       int PRIMARY KEY,
    severity text NOT NULL,
    cve      text NOT NULL
);

INSERT INTO vulns (id, severity, cve) VALUES
    (1, 'critical', 'CVE-2024-0001'),
    (2, 'high',     'CVE-2024-0002'),
    (3, 'medium',   'CVE-2024-0003'),
    (4, 'low',      'CVE-2024-0004'),
    (5, 'info',     'CVE-2024-0005')
ON CONFLICT (id) DO NOTHING;

-- Embedding table for PgVectorAdapter tests.
CREATE TABLE IF NOT EXISTS vuln_embeddings (
    id        int PRIMARY KEY,
    embedding vector(3) NOT NULL,
    metadata  jsonb     NOT NULL
);

INSERT INTO vuln_embeddings (id, embedding, metadata) VALUES
    (1, '[1,0,0]'::vector, '{"cve": "CVE-2024-0001", "severity": "critical"}'::jsonb),
    (2, '[0,1,0]'::vector, '{"cve": "CVE-2024-0002", "severity": "high"}'::jsonb),
    (3, '[0,0,1]'::vector, '{"cve": "CVE-2024-0003", "severity": "medium"}'::jsonb)
ON CONFLICT (id) DO NOTHING;
