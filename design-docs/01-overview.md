# Nautilus — Overview

> LLMs are better knowledge engineers than they are inference engines. CLIPS is a better inference engine than any LLM. Nautilus uses both where they're strongest.

**Status:** Design Draft v3
**License:** MIT (open source, built on Fathom)
**Language:** Python
**Package Manager:** uv
**DSL:** Fathom Rules (`fathom-rules` on PyPI) — compiles YAML rule definitions to CLIPS constructs
**Maintained by:** Kraken Networks

> This is part 1 of 5. See [README.md](./README.md) for the full set.

---

## Core Thesis

Everyone else uses LLMs to reason at query time — probabilistic, non-reproducible, unexplainable. Nautilus inverts this. LLMs do creative work at *maintenance time* — discovering relationships, suggesting rules, identifying patterns. A CLIPS expert system does reliable work at *runtime* — routing requests, enforcing policy, tracking exposure. The LLM is the knowledge engineer. CLIPS is the inference engine. Each does what it's best at.

The result is a knowledge system that retains and refines what it learns — executing like a machine at runtime (deterministic, auditable, explainable, sub-millisecond) while evolving its certainty factors and routing intelligence over time through a neural-network-equivalent learning process.

---

## The Problem

AI agents need data from multiple sources. Today, agents get direct access to databases via tools — MCP servers, function calls, RAG pipelines. The agent decides what to query, where to query it, and what to do with the results.

This creates four problems that get worse as organizations scale:

**1. Nobody tracks cumulative data exposure.**
Agent A reads PII from HR. Agent A's output goes into Agent B's context. Agent B queries finance. The combined knowledge now represents a data profile that neither agent was individually authorized to construct. No existing tool tracks this because no existing tool maintains state across queries. This is not a theoretical concern — it is an active compliance liability for any organization running multi-agent workflows against sensitive data, and no existing framework addresses it.

**2. Agents can't reason about what they don't know exists.**
An agent with tools for 3 of your 10 databases will never find relevant data in the other 7. Adding tools for all 10 means the agent must reason about which sources are relevant — a task LLMs handle unreliably, especially for unfamiliar schemas.

**3. Access control is bolted on, not reasoned about.**
Current solutions (Auth0 FGA, Permit.io, Oso) apply RBAC/ABAC filters at the query layer. They answer "is this agent allowed to access this table?" They don't answer "given this agent's clearance, purpose, and what it has already accessed this session, which sources should it see, what scope should each query have, and does the combination of accessed data create a classification escalation?"

**4. Organizational knowledge is static.**
Knowledge graphs require humans to build and maintain them. RAG pipelines retrieve what was indexed but don't discover new relationships. Nobody builds systems that actively learn the shape of an organization's data landscape and get better at routing over time.

---

## What Nautilus Is

Nautilus is an expert knowledge broker — less like a query router, more like a librarian who deeply understands the entire collection. It has three modes of operation that run simultaneously:

**The Librarian (request-time):** When an agent describes what it needs, Nautilus doesn't just find matching data — it identifies relevant sources the agent didn't know to ask about, enforces classification and access policy, transforms results as needed, and tracks cumulative exposure across the session.

**The Curator (maintenance-time):** Nautilus continuously maintains an evolving understanding of its data landscape — discovering relationships between sources, mapping overlap and gaps, refining routing intelligence, and proposing new rules based on observed patterns.

**The Gatekeeper (always):** Every data access decision is deterministic, auditable, and explainable. Every response includes a full reasoning trace and signed attestation. The system is fail-closed by default.

---

## Version Scope

Nautilus is designed in two major versions. v1 delivers the core value proposition — brokered data access with policy enforcement, cumulative exposure tracking, and auditable routing. v2 adds the Retentive Knowledge Model (RKM) — meta-rules, LLM knowledge engineering, expert network learning, proactive suggestions, and scaling architecture.

This separation is deliberate. v1 must stand alone as a useful, deployable system. No feature in v1 depends on v2. v2 builds on v1's foundation but does not retroactively change v1's interfaces or persistence model.

| Concern | v1 | v2 |
|---------|----|----|
| Intent analysis | Structured + pattern-matching | LLM-assisted (maintenance-time) |
| Routing | Rule-driven, manually authored | Self-evolving via meta-rules |
| Policy enforcement | Classification + RBAC/ABAC | Cumulative escalation rules |
| Exposure tracking | Per-session, per-agent | Cross-agent flow tracking |
| Suggestions | None (explicit routing only) | Proactive, affinity-based |
| Retentive Knowledge Model | Manual rule authoring | Meta-rules + LLM engineer + Expert Network learning |
| Confidence refinement | Static (human-assigned) | Expert Network backpropagation on certainty factors |
| Scaling | Single CLIPS instance | Blackboard multi-worker |
| Deployment | Standalone + container | + Air-gapped mode |

---

## How It Works

```
┌─────────┐     ┌───────────────────────────────────────────┐     ┌──────────┐
│  Agent   │────▶│              Nautilus                      │────▶│ Postgres │
│          │     │                                           │────▶│ pgvector │
│  "I need │     │  1. Parse intent                          │────▶│ Elastic  │
│  threat  │     │  2. Assert facts into CLIPS working memory│────▶│ S3/docs  │
│  intel   │     │  3. RETE fires routing + policy rules     │────▶│ REST APIs│
│  on CVE- │     │  4. Engine selects sources + scopes       │     └──────────┘
│  2026-   │     │  5. Execute scoped queries                │
│  1234"   │     │  6. Transform + synthesize results        │
│          │◀────│  7. Update session memory + audit log     │
│          │     │  8. Return with attestation token         │
└─────────┘     └───────────────────────────────────────────┘
                                    │
                        ┌───────────▼────────────┐
                        │   Background Curator    │
                        │   (v2 only)             │
                        │                        │
                        │  - Track request patterns│
                        │  - Discover relationships│
                        │  - Propose new rules    │
                        │  - Validate + promote   │
                        └────────────────────────┘
```

### What the agent sees:

```python
from nautilus import Broker

broker = Broker.from_config("nautilus.yaml")

response = broker.request(
    agent_id="agent-alpha",
    intent="Find all known vulnerabilities, patches, and affected systems for CVE-2026-1234",
    context={
        "clearance": "secret",
        "purpose": "threat-analysis",
        "workflow": "incident-response-42",
        "session_id": "sess-001"
    }
)

print(response.data)               # Synthesized results from multiple sources
print(response.sources_queried)    # ["nvd_db", "internal_vulns", "cmdb"]
print(response.sources_denied)     # ["hr_records"]
print(response.sources_skipped)    # ["marketing_db"] (not relevant)
print(response.suggestions)        # v2: ["3 related CVEs affect the same library — included"]
print(response.scope_restrictions) # {"cmdb": "asset_type IN ('server', 'network_device')"}
print(response.routing_trace)      # Full rule-by-rule reasoning
print(response.exposure_summary)   # Cumulative data types accessed this session
print(response.attestation_token)  # Signed proof of policy-checked access
```

---

## Intent Analysis

Intent analysis is the front door of Nautilus — the mechanism by which a natural language or structured request becomes a set of CLIPS facts that the routing engine can reason about. This section specifies how that translation works in both v1 and v2.

### v1: Structured Requests + Pattern-Matching Fallback

v1 supports two request modes. The preferred mode is structured requests where the agent explicitly declares the data types, filters, and purpose. This bypasses intent analysis entirely and asserts facts directly into working memory.

```python
# Structured request — no ambiguity, no analysis needed
response = broker.query(
    agent_id="agent-alpha",
    data_types=["vulnerability", "asset"],
    filters={"cve_id": "CVE-2026-1234"},
    context={"clearance": "secret", "purpose": "incident-response"}
)
```

For natural language requests, v1 uses a pattern-matching intent analyzer. This is not keyword extraction and not regex. It is a configurable pipeline with three stages:

**Stage 1 — Data Type Extraction.** The analyzer maintains a vocabulary of known data types drawn from the source registry. Each source declares the data types it serves (e.g., `cve`, `vulnerability`, `asset`, `employee`). The analyzer scans the intent string for exact and stemmed matches against this vocabulary, producing a candidate set of data types.

**Stage 2 — Purpose Classification.** A second vocabulary maps intent phrases to declared purposes. "What systems are affected" maps to `incident-response`. "Who has access to" maps to `access-audit`. This mapping is manually authored in a YAML configuration file. Unmatched intents receive a `general` purpose tag, which restricts routing to sources with no `allowed_purposes` constraint.

**Stage 3 — Filter Extraction.** A set of extraction patterns identify structured identifiers within natural language. CVE IDs (`CVE-\d{4}-\d{4,}`), IP addresses, hostnames, date ranges, and other domain-specific patterns are matched via configurable regex rules and asserted as filter facts.

```yaml
# config/intent-patterns.yaml
data_type_vocabulary:
  vulnerability: [vulnerability, vuln, CVE, exploit, weakness]
  asset: [system, server, host, device, machine, endpoint]
  patch: [patch, fix, update, remediation, hotfix]
  employee: [employee, user, person, staff, personnel]

purpose_mapping:
  incident-response: [affected, impact, compromise, breach, respond]
  threat-analysis: [threat, risk, exposure, attack, campaign]
  compliance-audit: [compliance, audit, regulation, policy, control]
  asset-management: [inventory, asset, configuration, deployed]

filter_patterns:
  - name: cve_id
    pattern: "CVE-\\d{4}-\\d{4,}"
    type: string
  - name: ip_address
    pattern: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
    type: string
  - name: date_range
    pattern: "(last|past)\\s+(\\d+)\\s+(days?|weeks?|months?)"
    type: relative_date
```

The output of intent analysis is a set of CLIPS facts:

```
(intent-data-type (type "vulnerability") (confidence 1.0) (source "vocabulary-match"))
(intent-data-type (type "asset") (confidence 1.0) (source "vocabulary-match"))
(intent-purpose (purpose "incident-response") (confidence 0.9) (source "purpose-mapping"))
(intent-filter (field "cve_id") (value "CVE-2026-1234") (source "pattern-match"))
```

When intent analysis produces low-confidence results (no data type matches, no purpose match), the broker returns a structured error asking the agent to either re-phrase or use a structured request. It does not guess. Fail-closed applies here too.

**Known limitations of v1 intent analysis:** It cannot handle ambiguous requests where the same term maps to multiple data types across different domains. It cannot infer intent from context that isn't explicitly stated. It cannot handle negation ("everything except HR data"). These are documented limitations, not bugs, and agents are expected to use structured requests for complex cases.

### v2: LLM-Assisted Intent Analysis (Maintenance-Time)

v2 does not add LLM inference at request time. Instead, the LLM knowledge engineer periodically reviews intent analysis logs — specifically cases where the pattern matcher returned low confidence or where agents immediately followed up with a refined query — and proposes new vocabulary entries, purpose mappings, or filter patterns. These proposals enter the standard rule validation pipeline before being promoted to the active configuration.

This means v2's intent analysis uses the same pattern-matching pipeline as v1, but with a vocabulary and mapping set that improves over time via supervised evolution.
