-- VE (verification environment) seed SQL for reasoning-engine Phase 5 (Task 5.1).
--
-- Loaded after tests/fixtures/seed.sql. Responsibilities:
--   1. Expand the Phase-1 ``vuln_embeddings`` dataset with rows keyed to the
--      AC-12.4 end-to-end scenario (PII + CTI mixed payloads so the
--      pattern-matcher fires the ``pii-aggregation-confidential`` and
--      ``escalation-confidential`` rules once VE2a exercises ``/v1/request``).
--   2. Provision an ``agents`` mirror table so AgentRegistry parity tests
--      (Task 5.2-5.4) can cross-check the two declared identities
--      (``orch-a`` clearance=secret, ``orch-b`` clearance=cui) against a
--      relational view. The live AgentRegistry still reads from YAML
--      (design §3.5, FR-9) — this table is informational for VE assertions
--      only, NOT a new authoritative source.
--
-- Design refs: FR-9, FR-25, FR-27, AC-12.4, design §7.1.

-- Mirror of YAML ``agents:`` block — identity, clearance, compartments.
CREATE TABLE IF NOT EXISTS agents (
    id            text PRIMARY KEY,
    clearance     text        NOT NULL,
    compartments  text[]      NOT NULL DEFAULT '{}',
    default_purpose text
);

INSERT INTO agents (id, clearance, compartments, default_purpose) VALUES
    ('orch-a', 'secret', ARRAY['cti'],     'threat-hunt'),
    ('orch-b', 'cui',    ARRAY[]::text[], NULL)
ON CONFLICT (id) DO UPDATE
    SET clearance        = EXCLUDED.clearance,
        compartments     = EXCLUDED.compartments,
        default_purpose  = EXCLUDED.default_purpose;

-- Additional embeddings carrying PII keywords so pattern-matcher routing
-- assertions have positive + negative rows to match against.
INSERT INTO vuln_embeddings (id, embedding, metadata) VALUES
    (10, '[0.1,0.2,0.3]'::vector,
         '{"cve": "CVE-2024-1010", "severity": "critical", "tags": ["pii", "email", "phone"]}'::jsonb),
    (11, '[0.2,0.1,0.4]'::vector,
         '{"cve": "CVE-2024-1011", "severity": "high",     "tags": ["cti", "ioc"]}'::jsonb),
    (12, '[0.3,0.3,0.1]'::vector,
         '{"cve": "CVE-2024-1012", "severity": "medium",   "tags": ["pii", "dob"]}'::jsonb)
ON CONFLICT (id) DO NOTHING;
