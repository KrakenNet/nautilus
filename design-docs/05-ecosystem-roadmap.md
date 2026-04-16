# Nautilus — Ecosystem, Testing, and Roadmap

> *Part 5 of 5 — Fathom/Bosun, RETE, testing, out-of-scope, known weaknesses, roadmap, open source, Knowledge Federation. See also:* [01-overview](./01-overview.md) · [02-core-engine](./02-core-engine.md) · [03-living-brain](./03-living-brain.md) · [04-architecture-operations](./04-architecture-operations.md)

---

## Relationship to Fathom and Bosun

```
Agent submits intent
        │
        ▼
   ┌─────────┐
   │ Nautilus │──── "What does this agent need and what can it see?"
   │         │      Uses Fathom for routing, policy, suggestions
   │         │      (v2) Evolves knowledge through meta-rules + LLM engineer
   └────┬────┘
        │
        ▼
   Data returned to agent
        │
        ▼
   Agent takes action
        │
        ▼
   ┌─────────┐
   │  Bosun   │──── "Is this agent allowed to take this action?"
   │         │      Uses Fathom for governance decisions
   └─────────┘
```

Nautilus governs what agents **know**. Bosun governs what agents **do**. Both use Fathom as their reasoning engine.

---

## RETE Algorithm

CLIPS uses the RETE algorithm for pattern matching. RETE is eager and data-oriented — when a fact is asserted, it immediately propagates through the network finding all partial matches. For Nautilus's expected working memory sizes (hundreds of rules, thousands to tens-of-thousands of facts), RETE performs well within sub-millisecond targets.

Newer algorithms exist — notably PHREAK (used in Drools), which is lazy and goal-oriented, deferring partial matching until rules are candidates for firing. PHREAK scales better for very large rule bases (10,000+ rules) and degrades more gracefully. However, PHREAK only exists in Java/Drools. There is no Python implementation.

Nautilus stays on CLIPS/RETE because: clipspy is actively maintained (Python 3.9-3.14), the working memory sizes are within RETE's sweet spot, and the Blackboard scaling pattern bounds per-worker memory regardless of algorithm. If RETE becomes a bottleneck at scale, the correct response is sharding via the Blackboard pattern, not switching inference algorithms.

---

## Testing Strategy

### Rule Unit Tests

Rules are testable in isolation. Fathom provides a test runner that loads a rule, asserts a set of input facts, runs the engine, and verifies the resulting facts.

```yaml
# tests/routing/test-route-to-nvd.yaml
test: route-to-nvd
setup:
  facts:
    - template: intent
      slots:
        data_types_needed: ["cve"]
        session_id: "test-001"
        agent_id: "test-agent"
        clearance: "unclassified"
        purpose: "threat-analysis"
    - template: source_metadata
      slots:
        source_id: "nvd_db"
        data_types: ["cve", "vulnerability", "patch"]
        classification: "unclassified"
expect:
  facts:
    - template: routing_decision
      slots:
        source: "nvd_db"
        decision: allow
```

### Integration Tests

Integration tests run full request lifecycles against mock adapters. Mock adapters return canned data and verify that scope constraints were correctly applied.

### Exposure Tracking Tests

Dedicated test suite for cumulative exposure scenarios. Each test defines a sequence of requests within a session and verifies that exposure flags are raised at the correct points.

### v2: Sandbox Regression Suite

The sandbox validation pipeline doubles as a regression suite. Every rule change (manual or auto-generated) is validated against the full historical request log before promotion.

---

## Explicitly Not In Scope

- **FuzzyCLIPS** — Unmaintained, incompatible with clipspy/CLIPS 6.41. Fuzzy scoring implemented via custom deffunctions instead.
- **Neo4j or any graph database** — Relationships are CLIPS facts. Persistence is Postgres/SQLite. Graph visualization can be generated from serialized facts if needed for admin UI.
- **PHREAK or alternative inference algorithms** — Only exists in Java/Drools. CLIPS/RETE handles expected working memory sizes. Blackboard pattern handles scaling.
- **Backward chaining** — Forward chaining covers all current use cases.
- **Real-time LLM reasoning at query time** — LLMs operate at maintenance time only. Runtime is deterministic CLIPS.
- **Serverless deployment** — CLIPS working memory deserialization cost makes cold starts unacceptable.
- **Semantic result synthesis in v1** — Requires schema knowledge that the Retentive Knowledge Model (v2) builds over time.
- **Cross-system exposure tracking in v1** — Requires integration with agent orchestration layer beyond Nautilus's boundary.
- **Knowledge Federation (cross-instance knowledge sharing)** — Depends on stable Retentive Knowledge Model and battle-tested validation pipeline. Sketched in Future Directions as a v3 concept. Not roadmapped.

---

## Known Weaknesses, Mitigations, and Open Questions

This section documents limitations the design acknowledges, the planned or recommended mitigations for each, and any residual risk that remains.

### 1. Session boundary is caller-declared

**Weakness:** Nautilus trusts the calling agent or orchestrator to correctly declare `session_id`. A malicious or buggy agent can evade exposure tracking by using a new session_id for every request. Nautilus has no mechanism to independently verify that two requests are part of the same logical workflow.

**Mitigation: Session provenance tokens.** Instead of trusting the caller's raw `session_id`, Nautilus issues a signed session token on first use. The token is a JWT containing the originating `agent_id`, creation timestamp, and a session nonce. Subsequent requests in the same session must present this token. If Agent B wants to join Agent A's session, the orchestrator must explicitly hand off Agent A's session token — Nautilus verifies the signature and records the handoff in the audit log.

```python
# First request — Nautilus issues a session token
response = broker.request(
    agent_id="agent-a",
    intent="...",
    context={"clearance": "secret", "purpose": "incident-response"}
)
session_token = response.session_token  # Signed JWT

# Agent B joins the session — must present Agent A's token
response = broker.request(
    agent_id="agent-b",
    intent="...",
    context={
        "clearance": "secret",
        "purpose": "incident-response",
        "session_token": session_token
    }
)
```

**Residual risk:** A malicious orchestrator that holds the signing key can still forge session tokens. This mitigation moves the trust boundary from "any agent" to "the orchestrator," which is a meaningful reduction in attack surface. For environments requiring stronger guarantees, Bosun should enforce session lifecycle policies at the orchestration layer and audit token handoffs.

**Implementation:** v1. Session token issuance and verification is low-complexity (JWT signing is a solved problem) and directly strengthens the exposure tracking system.

### 2. Cross-agent exposure requires honest reporting

**Weakness:** Cross-agent exposure tracking (v2) assumes that when Agent B operates in a session started by Agent A, the orchestrator correctly passes the session token. If agents communicate outside Nautilus (via shared files, message queues, or direct LLM context injection), Nautilus cannot observe the data flow. This is a fundamental limitation of any system that operates as a broker rather than a proxy — it can only track what flows through it.

**Mitigation: Mandate Nautilus as the sole data access path.** At the organizational level, network policy should enforce that agents cannot reach data sources directly — all data access routes through Nautilus. This is enforced at the infrastructure layer (firewall rules, service mesh policies), not within Nautilus itself. When this policy is in place, the only remaining blind spot is agent-to-agent communication that doesn't involve data source queries.

For the residual agent-to-agent blind spot, Bosun should require agents to declare their context sources when taking actions. This creates an audit trail of claimed provenance: "Agent B declares that its context includes output from Agent A's session X." Nautilus can then retroactively correlate Agent B's session with Agent A's exposure state, even if the data flow didn't pass through the broker.

```yaml
# Bosun action policy (conceptual — Bosun's design is separate)
rules:
  - name: require-context-declaration
    when:
      action_request:
        agent_id: $agent
      not:
        context_declaration:
          agent_id: $agent
    then:
      action: deny_action
      reason: "Agent must declare context sources before taking action"
```

**Residual risk:** Agents can lie about their context sources. This is a trust boundary inherent to any system that doesn't proxy all inter-agent communication. Full inter-agent data flow tracking would require a fundamentally different architecture (an agent communication bus), which is out of scope for Nautilus.

**Implementation:** Network policy enforcement is an operational concern, not a Nautilus feature. Context declaration is a Bosun feature. Nautilus's contribution is providing the session provenance tokens that make correlation possible.

### 3. Intent analysis vocabulary maintenance burden

**Weakness:** The v1 pattern-matching intent analyzer relies on manually curated vocabularies. As the number of sources and data types grows, keeping vocabularies accurate becomes an operational burden.

**Mitigation:** v2's LLM knowledge engineer periodically reviews intent analysis logs — specifically low-confidence results and immediate retry patterns — and proposes vocabulary and purpose mapping updates. These proposals go through the standard validation pipeline. Additionally, the source registry already declares `data_types` per source, so the data type vocabulary can be partially auto-generated from the registry on startup, reducing the manual authoring surface to synonyms and purpose mappings.

**Residual risk:** v1 operators must maintain vocabularies manually until v2 is deployed. For organizations with fewer than 20 sources, this is manageable. For larger deployments, structured requests should be the primary interface and natural language requests treated as a convenience layer.

**Implementation:** Auto-generation of base vocabulary from source registry is v1 (low effort). LLM-assisted vocabulary evolution is v2.

### 4. Working memory serialization is a crash window

**Weakness:** Between CLIPS fact assertion and the synchronous persistence write, there is a window (measured in microseconds) where a crash would lose the current request's state.

**Mitigation:** For v1, the synchronous persistence write minimizes this window. The accepted worst case is loss of one request's exposure update on crash — the session continues with the previous exposure state. For environments requiring zero data loss, v1 adds an optional local write-ahead log (WAL) mode: before asserting facts into CLIPS, the broker writes the intended fact operations to a local append-only file. On crash recovery, the WAL is replayed before deserializing from the database.

```yaml
# nautilus.yaml
persistence:
  mode: synchronous        # default
  wal_enabled: false        # enable for zero-loss environments
  wal_path: /var/nautilus/wal
```

**Residual risk:** WAL mode adds ~0.5ms of latency per request (local disk write). For most deployments, the default synchronous mode with one-request-loss acceptance is the right tradeoff.

**Implementation:** v1. The WAL is a simple append-only file with fact operations serialized as JSON lines. Replay logic runs during the existing deserialization step on startup.

### 5. Single-writer persistence model

**Weakness:** v1's single CLIPS instance means a single writer to the persistence layer. The v2 Blackboard architecture needs a more sophisticated persistence strategy.

**Mitigation: Event-sourcing model for v2.** Workers emit events (fact asserted, fact retracted, rule fired) to a shared event log rather than writing directly to the persistence layer. The coordinator consumes events for global state aggregation. Each worker owns a persistence partition for its domain-specific facts.

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│ Worker A │     │ Worker B │     │ Worker C │
│          │     │          │     │          │
│ emits    │     │ emits    │     │ emits    │
│ events   │     │ events   │     │ events   │
└────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │
     ▼                ▼                ▼
┌─────────────────────────────────────────────┐
│            Shared Event Log                  │
│  (Postgres LISTEN/NOTIFY or NATS)            │
│                                             │
│  Events: fact_asserted, fact_retracted,     │
│          rule_fired, exposure_updated        │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────┐
│            Coordinator                        │
│  Consumes events → updates global state       │
│  Writes aggregated state to persistence       │
│  Single writer for cross-domain facts         │
└──────────────────────────────────────────────┘
```

This avoids write contention and produces a replayable event history as a side effect — useful for debugging and for the sandbox validation pipeline, which can replay events instead of re-executing requests.

**Residual risk:** Event ordering across workers is not guaranteed without a total-order log (which adds latency). For most cross-domain operations, eventual consistency is acceptable — the coordinator merges results after all workers respond to a given request. For exposure tracking, the coordinator applies exposure facts synchronously during result merging, so ordering within a single request is guaranteed.

**Implementation:** v2 design spike (weeks 11-12). The event log infrastructure must be validated before committing to the Blackboard timeline.

### 6. No schema evolution story

**Weakness:** If a source's schema changes (columns added, renamed, or removed), routing rules, scope constraints, and transformation rules that reference those columns break silently.

**Mitigation: Schema fingerprinting.** Each adapter queries its source's schema (column names, types) on startup and on a configurable interval (default: hourly). The schema is hashed and stored as a CLIPS fact.

```yaml
# templates/schema.yaml
templates:
  - name: source_schema
    slots:
      - name: source_id
        type: string
        required: true
      - name: schema_hash
        type: string
        required: true
      - name: columns
        type: multifield
      - name: last_checked
        type: float
      - name: status
        type: symbol
        allowed_values: [current, drifted, unknown]
```

When the hash changes between checks, a `schema_drift` fact is asserted. A policy rule fires:

```yaml
rules:
  - name: quarantine-drifted-source
    salience: 200
    when:
      source_schema:
        source_id: $source
        status: drifted
      routing_decision:
        source: $source
        decision: allow
    then:
      action: modify
      fact: routing_decision
      slots:
        decision: quarantine
        reason: "Schema drift detected — source quarantined pending human review"
      log: full
```

Quarantined sources are excluded from routing until an operator confirms the new schema and updates relevant rules. The admin UI (v2) surfaces quarantined sources prominently.

**Residual risk:** Schema fingerprinting catches structural changes but not semantic changes (e.g., a column's meaning changes without its type changing). This is an inherent limitation — only human review can catch semantic drift.

**Implementation:** Schema fingerprinting and quarantine rules are v1 (low-moderate effort — each adapter needs a `get_schema()` method). Admin UI surfacing is v2.

### 7. Attestation token does not prove data integrity

**Weakness:** The attestation token proves that Nautilus evaluated the policy and made specific routing decisions. It does not prove that the data returned by the adapters was not tampered with in transit.

**Mitigation (v1): Adapter response hashing.** Each adapter computes a SHA-256 hash of its raw response before scope filtering or transformation. The hash is included in the adapter's return value and recorded in the attestation token. This proves that the data Nautilus received from the source matches what it returned to the agent (after any documented transformations). It does not prove the source itself was not compromised — only that nothing changed between the source response and the agent response.

```python
class BaseAdapter:
    def execute(self, query_intent, scope_constraints):
        raw_response = self._query(query_intent, scope_constraints)
        response_hash = hashlib.sha256(
            json.dumps(raw_response, sort_keys=True).encode()
        ).hexdigest()
        return AdapterResult(
            data=raw_response,
            response_hash=response_hash
        )
```

**Mitigation (v2): Adapter-level signing.** For high-assurance environments, adapters sign their responses with adapter-specific keys. The adapter SDK provides a signing mixin. Nautilus includes adapter signatures in the attestation token, enabling end-to-end non-repudiation: a downstream system can verify that (a) Nautilus made the routing decision it claims, and (b) each adapter returned the data it claims.

```python
class SigningAdapter(BaseAdapter, SigningMixin):
    def __init__(self, config, signing_key):
        super().__init__(config)
        self.signing_key = signing_key

    def execute(self, query_intent, scope_constraints):
        result = super().execute(query_intent, scope_constraints)
        result.signature = self.sign(result.response_hash, self.signing_key)
        return result
```

**Residual risk:** Neither mitigation protects against a compromised data source returning falsified data. That is a source-integrity problem outside Nautilus's scope. Nautilus guarantees policy enforcement and chain-of-custody from source to agent — not source trustworthiness.

**Implementation:** Response hashing is v1 (trivial per-adapter addition). Adapter signing SDK is v2.

### 8. Meta-rule observation window bias (v2)

**Weakness:** The meta-rule pattern tracker observes sequential requests within a 5-minute window. Patterns that occur over longer timescales (e.g., weekly compliance workflows) may never reach the observation count threshold for promotion.

**Mitigation: Multi-timescale observation rulesets.** Add a second tier of meta-rules that operate on aggregated access logs rather than real-time facts. The `weekly-pattern-tracker` ruleset runs as a scheduled maintenance task (daily), aggregates access_log facts by calendar week and agent purpose, and looks for recurring data type sequences.

```yaml
# rules/meta/weekly-pattern-tracker.yaml
ruleset: weekly-pattern-tracker
module: curator
version: 1.0

rules:
  - name: track-weekly-recurring-pattern
    description: "Detect data type sequences that recur on a weekly basis"
    when:
      weekly_access_summary:
        week: $week_a
        agent_purpose: $purpose
        data_type_sequence: $seq
      weekly_access_summary:
        week: $week_b
        agent_purpose: $purpose
        data_type_sequence: $seq
        constraint: "$week_b - $week_a <= 2"
      not:
        weekly_relationship_candidate:
          data_type_sequence: $seq
          purpose: $purpose
    then:
      action: assert
      fact:
        template: weekly_relationship_candidate
        slots:
          data_type_sequence: $seq
          purpose: $purpose
          observation_count: 1
      log: summary

  - name: promote-weekly-pattern
    description: "Promote weekly patterns after 6 weekly observations"
    when:
      weekly_relationship_candidate:
        data_type_sequence: $seq
        purpose: $purpose
        observation_count: greater_than(5)
    then:
      action: propose_rule
      rule:
        name: "auto-weekly-{$purpose}-{$seq}"
        module: suggestions
        description: "Auto-discovered weekly pattern: {$purpose} workflows consistently access {$seq}"
        # ... (standard suggestion rule format)
      validation: sandbox
      log: full
```

The promotion threshold is lower (6 weekly observations vs. 10 sequential) because weekly patterns are inherently slower to observe. The freshness_weight deffunction already supports configurable half-lives, so decay logic works at both timescales without modification.

**Residual risk:** Patterns that occur on even longer cycles (monthly, quarterly) require proportionally longer observation periods. There is a practical limit to how long the system must observe before confidently identifying a pattern. Monthly patterns are addressable with an additional ruleset tier. Quarterly and beyond are better served by the LLM knowledge engineer, which can analyze longer historical windows in a single prompt.

**Implementation:** v2. The weekly pattern tracker depends on access log aggregation infrastructure, which is a natural extension of the audit log.

---

## Development Roadmap

### v1 — Core Broker (Weeks 1-10)

*Requires: Fathom Phase 1 complete*
*Team assumption: 2 engineers full-time*

**Weeks 1-3: Foundation**
- [ ] Project scaffolding with uv
- [ ] Source registry with YAML configuration
- [ ] Intent analyzer: vocabulary loader, purpose mapper, filter extractor
- [ ] Intent analyzer: auto-generated base vocabulary from source registry `data_types`
- [ ] Intent analyzer: confidence scoring and structured error on low confidence
- [ ] Fathom integration for routing decisions
- [ ] CLIPS working memory lifecycle (initialize, assert, run, retract)
- [ ] CLIPS lock and request serialization

**Weeks 4-6: Adapters and Policy**
- [ ] PostgreSQL adapter with parameterized scope enforcement
- [ ] pgvector adapter with metadata filtering
- [ ] Adapter error handling and `sources_failed` reporting
- [ ] Adapter response hashing (SHA-256, included in attestation token)
- [ ] Adapter `get_schema()` method and schema fingerprinting
- [ ] Schema drift detection and source quarantine policy rules
- [ ] Classification hierarchy support
- [ ] Policy module: clearance checks, purpose enforcement
- [ ] Session provenance tokens: JWT issuance, signature verification, handoff audit
- [ ] Cumulative exposure tracking: session model, exposure facts
- [ ] Exposure policy rules: classification escalation, cross-agent flags
- [ ] Fail-closed enforcement at all layers

**Weeks 7-8: Synthesis, Persistence, Interface**
- [ ] Result synthesizer (structured merge, grouped by source)
- [ ] Persistence layer (Postgres with SQLite fallback)
- [ ] Working memory serialization/deserialization
- [ ] Session persistence (synchronous write after each request)
- [ ] Optional write-ahead log (WAL) mode for zero-loss environments
- [ ] Audit log (append-only)
- [ ] Attestation token generation (HMAC-SHA256, includes adapter response hashes)
- [ ] Python SDK
- [ ] REST API (FastAPI)

**Weeks 9-10: Hardening**
- [ ] Consistency checks after each engine run
- [ ] Health check endpoint (readiness gating on deserialization)
- [ ] Prometheus metrics endpoint
- [ ] Structured JSON logging
- [ ] Rule unit test runner
- [ ] Integration test suite with mock adapters
- [ ] Exposure tracking test suite
- [ ] Docker container image
- [ ] MCP tool server
- [ ] Documentation: operator guide, rule authoring guide, adapter development guide

### v2 — Retentive Knowledge Model and Scale (Weeks 11-24)

*Requires: v1 deployed and stable*
*Team assumption: 2-3 engineers*

**Weeks 11-14: Retentive Knowledge Model Foundation**
- [ ] Event-sourcing design spike: validate shared event log for Blackboard persistence
- [ ] Relationship facts (templates + initial manual authoring)
- [ ] Meta-rules: pattern tracking and relationship candidate detection
- [ ] Meta-rules: auto-promotion of high-confidence relationships
- [ ] Rule validation pipeline: static analysis (Fathom integration)
- [ ] Rule validation pipeline: shadow/subsumption check
- [ ] Rule validation pipeline: sandbox execution against audit log
- [ ] Rule validation pipeline: confidence scoring and promotion/rejection
- [ ] Human review queue for medium-confidence proposals
- [ ] Rule rollback and lineage tracking

**Weeks 15-18: LLM Engineer, Suggestions, Transforms**
- [ ] LLM knowledge engineer (maintenance-time rule suggestion)
- [ ] LLM-assisted vocabulary and intent pattern updates
- [ ] Proactive suggestion rules and suggestion module
- [ ] Multi-timescale observation rulesets (weekly pattern tracker, access log aggregation)
- [ ] Fathom DSL: `certainty` declaration support for rules
- [ ] Similarity scoring deffunctions
- [ ] Freshness decay and knowledge garbage collection
- [ ] Data transformation rules (redaction, aggregation, normalization, conflict resolution)
- [ ] Elasticsearch adapter
- [ ] REST API adapter

**Weeks 19-22: Cross-Agent Tracking and Scale**
- [ ] Cross-agent information flow tracking
- [ ] Classification escalation rules (dynamic, based on exposure combinations)
- [ ] Blackboard architecture: coordinator + domain workers
- [ ] Event-sourcing persistence: worker event emission, coordinator consumption
- [ ] Cross-worker relationship facts in coordinator CLIPS
- [ ] ServiceNow adapter
- [ ] Air-gapped deployment mode

**Weeks 23-24: Ecosystem, Admin, and Expert Networks**
- [ ] Admin UI: knowledge landscape viewer, rule proposals, audit trail
- [ ] Admin UI: schema drift quarantine dashboard
- [ ] Expert Network parser: CLIPS rule base → network structure translation
- [ ] Expert Network training: audit log → labeled training dataset extraction
- [ ] Expert Network refinement: backpropagation on certainty factors with validation pipeline integration
- [ ] S3/document store adapter
- [ ] Custom adapter SDK with documentation
- [ ] Adapter signing SDK (response-level signatures for high-assurance environments)
- [ ] Rule packs: data-routing-nist, data-routing-hipaa
- [ ] Grafana dashboard templates
- [ ] Benchmarking suite (RETE performance at various working memory sizes)

---

## Open Source Strategy

- **License:** MIT
- **Core principle:** Nautilus is fully open source. Commercial value comes from professional services (deployment, custom adapters, classification policy development, knowledge engineering), the Bosun governance layer, and enterprise support.
- **Community:** Adapter contributions and meta-rule patterns especially welcome.
- **Blog cadence:** Launch post explaining the "LLMs as knowledge engineers, CLIPS as inference engine" thesis. Follow with demos showing the Retentive Knowledge Model in action — expert network learning, certainty factor refinement, and meta-rule discovery.
- **Demo:** Reference deployment with 5 data sources, multiple agent personas, showing: routing decisions, cumulative exposure tracking with classification escalation, proactive suggestions (v2), a relationship being auto-discovered over 10 requests (v2), and the full audit trail. This demo is the primary marketing asset.

---

## Future Direction: Knowledge Federation

The v2 Blackboard architecture introduces multiple specialized CLIPS instances within a single Nautilus deployment. Knowledge Federation extends this concept across organizational boundaries: multiple independent Nautilus instances that selectively share learned knowledge without sharing data, access logs, or session state.

This is not roadmapped. It is a v3 concept or a separate project, contingent on v2's Retentive Knowledge Model being stable and the knowledge representation (relationship facts, affinity scores, certainty factors, rule templates) having settled. What follows is a design sketch, not a commitment.

### The Opportunity

Organization A's Nautilus has learned (via meta-rules) that agents requesting vulnerability data almost always follow up with asset inventory queries. Organization B has independently learned the same pattern. Today, each organization discovers this in isolation. If they could share the abstracted pattern — the `data_type_affinity` fact — without sharing the underlying access logs, both systems get smarter faster with fewer observations.

This generalizes beyond pairs. A network of 50 Nautilus instances, each observing different agent populations and data landscapes, collectively discovers routing patterns that no single instance could observe alone. The network effect compounds: each new participant contributes observations and benefits from everyone else's.

### What Can Be Shared

The sharing boundary is determined by what encodes patterns versus what encodes operational data:

**Shareable (encodes patterns, not data):**
- `data_type_affinity` facts — co-occurrence strength between abstract data types
- `source_relationship` facts — but only with source_id replaced by source_type (e.g., "postgres-vulnerability" instead of "nvd_db"), preventing identification of specific sources
- Rule templates — auto-generated suggestion rules with source-specific identifiers stripped
- Vocabulary and purpose mapping updates — new synonyms, new purpose categories
- Expert network refined certainty factors — connection weights learned from local training, stripped of source-specific identifiers. A peer's learned certainty of 0.91 for "vulnerability requests with incident-response purpose should include asset data" is transferable knowledge even without knowing which specific sources were involved

**Not shareable (encodes operational data):**
- `access_log` facts — who queried what, when
- `session_exposure` facts — what agents have seen
- Source registry configurations — connection strings, schemas, classifications
- Attestation tokens and audit logs

### Trust Model

A rule or fact received from a peer Nautilus instance is treated identically to a rule proposed by the LLM knowledge engineer: it enters the standard validation pipeline. The proposer metadata records the peer's identity:

```yaml
# A rule received from a peer
rule:
  name: "peer-suggest-vulnerability-with-asset"
  proposed_by: "peer-nautilus-org-b"
  proposed_at: "2026-09-15T14:30:00Z"
  peer_confidence: 0.92
  peer_observation_count: 847
  # Local validation still required:
  local_validation: pending
  local_confidence: null
```

No special trust is granted to peer-originated rules. High peer confidence may inform the human reviewer's decision, but it does not bypass sandbox execution or confidence scoring. A rule that works well in Organization B's data landscape may cause regressions in Organization A's — the local sandbox is the arbiter.

Peer identity is established via mutual TLS. Each Nautilus instance in the network holds a certificate issued by a shared CA (or a federation of CAs for cross-organizational trust). Peer discovery can be static (configured list of peer endpoints) or dynamic (a registry service).

### Classification Boundary Enforcement

This is the hard problem. If Organization A operates at `secret` and Organization B at `unclassified`, sharing even abstracted patterns could leak classification-relevant information. The existence of a high-affinity relationship between "signals-intelligence" and "geospatial" data types might itself be classified — it reveals something about how classified workflows operate.

Knowledge Federation participation must be gated by a cross-domain policy. Nautilus's own policy engine evaluates each outbound share:

```yaml
# rules/policy/peer-sharing.yaml
rules:
  - name: block-classified-type-sharing
    description: "Do not share affinity facts that reference data types associated with classified sources"
    when:
      outbound_share:
        fact_type: data_type_affinity
        type_a: $type_a
      source_metadata:
        data_types: contains($type_a)
        classification: greater_than("cui")
    then:
      action: block_share
      reason: "Data type '{$type_a}' is associated with classified sources — sharing blocked"
      log: full
```

For organizations operating entirely at unclassified, this policy allows unrestricted sharing. For mixed-classification environments, only patterns involving unclassified data types flow to peers. For fully classified environments, Knowledge Federation participation is disabled (consistent with air-gapped mode).

### Network Topology

Knowledge Federation does not require full mesh connectivity. Three topologies are viable:

**Hub-and-spoke:** A central aggregator collects patterns from all participants and redistributes validated patterns. Simple to manage, single point of failure, and the hub sees all patterns (which may be unacceptable for competitive organizations).

**Peer-to-peer:** Each instance shares directly with configured peers. No central authority. Patterns propagate through the network via transitive sharing (A shares with B, B shares with C). Slower convergence but no single point of trust.

**Consortium:** A subset of instances form a sharing group with mutual agreements. Multiple consortiums can exist. An instance can participate in multiple consortiums with different sharing policies per consortium. This mirrors how real-world threat intelligence sharing (ISACs) operates.

### Prerequisites

Knowledge Federation depends on:
1. **Stable knowledge representation.** The `data_type_affinity` and `source_relationship` fact schemas must be settled — schema changes after federation is deployed would require coordinated migration across all peers.
2. **Battle-tested validation pipeline.** The sandbox and confidence scoring must be reliable enough that peer-originated rules cannot degrade local performance.
3. **Classification policy maturity.** The outbound sharing policy rules must be thoroughly tested against classification leakage scenarios.
4. **Operational trust.** Organizations must agree on sharing terms, which is a legal and business concern beyond Nautilus's technical scope.

None of these prerequisites are met today. Knowledge Federation is the logical destination of the Retentive Knowledge Model architecture, but it is not the next step. v1 and v2 must prove themselves first.
