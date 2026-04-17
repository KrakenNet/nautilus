-- Nautilus showcase: Postgres seed data.
-- Auto-runs via docker-entrypoint-initdb.d on first start.

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          SERIAL PRIMARY KEY,
    cve_id      TEXT UNIQUE NOT NULL,
    severity    TEXT NOT NULL,              -- critical, high, medium, low
    description TEXT NOT NULL,
    affected    TEXT NOT NULL,              -- product/component name
    published   TIMESTAMP NOT NULL DEFAULT now(),
    patched     BOOLEAN NOT NULL DEFAULT FALSE,
    patch_url   TEXT
);

INSERT INTO vulnerabilities (cve_id, severity, description, affected, published, patched, patch_url) VALUES
('CVE-2024-0001', 'critical', 'Remote code execution in authentication module via crafted JWT token', 'auth-service v2.3', '2024-01-15', TRUE, 'https://example.com/patches/0001'),
('CVE-2024-0002', 'high', 'SQL injection in user search endpoint allows data exfiltration', 'api-gateway v1.8', '2024-02-20', TRUE, 'https://example.com/patches/0002'),
('CVE-2024-0003', 'critical', 'Privilege escalation through misconfigured RBAC policy evaluation', 'policy-engine v3.1', '2024-03-10', FALSE, NULL),
('CVE-2024-0004', 'medium', 'Cross-site scripting in admin dashboard comment rendering', 'admin-ui v4.2', '2024-04-05', TRUE, 'https://example.com/patches/0004'),
('CVE-2024-0005', 'low', 'Information disclosure via verbose error messages in debug mode', 'logging-svc v1.0', '2024-04-18', TRUE, NULL),
('CVE-2024-0006', 'high', 'Denial of service via unbounded memory allocation in file upload', 'storage-svc v2.0', '2024-05-01', FALSE, NULL),
('CVE-2024-0007', 'critical', 'Supply chain compromise in third-party dependency: backdoored build artifact', 'ci-pipeline v1.5', '2024-05-22', TRUE, 'https://example.com/patches/0007'),
('CVE-2024-0008', 'medium', 'Insecure default configuration exposes metrics endpoint without auth', 'monitoring v3.4', '2024-06-10', FALSE, NULL),
('CVE-2024-0009', 'high', 'Certificate validation bypass in mutual TLS implementation', 'mesh-proxy v2.1', '2024-07-03', TRUE, 'https://example.com/patches/0009'),
('CVE-2024-0010', 'low', 'Race condition in session cleanup leads to stale session reuse', 'session-mgr v1.2', '2024-07-15', FALSE, NULL),
('CVE-2024-0011', 'critical', 'Unauthenticated API endpoint allows database schema enumeration', 'api-gateway v1.9', '2024-08-01', FALSE, NULL),
('CVE-2024-0012', 'high', 'Deserialization of untrusted data in inter-service message bus', 'event-bus v2.4', '2024-08-20', TRUE, 'https://example.com/patches/0012');
