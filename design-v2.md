# Nautilus — Rules-Based Knowledge Engine for AI Agents

> LLMs are better knowledge engineers than they are inference engines. CLIPS is a better inference engine than any LLM. Nautilus uses both where they're strongest.

**Status:** Design Draft v3
**License:** MIT (open source, built on Fathom)
**Language:** Python
**Package Manager:** uv
**DSL:** Fathom Rules (`fathom-rules` on PyPI) — compiles YAML rule definitions to CLIPS constructs
**Maintained by:** Kraken Networks

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

---

## Cumulative Exposure Tracking

This is Nautilus's most novel contribution and the hardest unsolved problem in multi-agent data governance. This section specifies how it works at the mechanical level.

### The Problem in Detail

Consider three agents in an incident response workflow:

1. **Agent A** queries HR for employee clearance levels for a department. It receives: names, roles, clearance tiers. Classification: PII.
2. **Agent A** passes its analysis to **Agent B**, which queries finance for department budget allocations. Agent B now has PII-derived context (it knows which people are in the department) combined with financial data.
3. **Agent B** passes results to **Agent C**, which queries the CMDB for systems those employees administer. Agent C now possesses a composite profile: who works there, what they're cleared for, how much they cost, and what systems they control.

No individual query violated policy. Each agent accessed sources within its clearance. But the *aggregate* represents an insider-threat-grade dossier that no single agent was authorized to construct. Current authorization frameworks cannot detect this because they evaluate queries in isolation.

### Session Model

Nautilus tracks exposure through sessions. A session is a logical unit of work that may span multiple agents and multiple requests. Sessions are identified by a `session_id` provided by the calling agent or orchestrator.

```python
# The orchestrator creates a session and passes it to all agents in the workflow
session_id = "incident-response-42"

# Agent A's request
broker.request(agent_id="agent-a", intent="...", context={"session_id": session_id, ...})

# Agent B's request — same session, different agent
broker.request(agent_id="agent-b", intent="...", context={"session_id": session_id, ...})
```

**Who creates sessions?** The orchestrator or workflow engine. Nautilus does not create sessions implicitly. If an agent does not provide a `session_id`, the request is treated as a standalone query with no cumulative tracking. This is a deliberate design choice: Nautilus cannot infer workflow boundaries, so it requires the caller to declare them.

**Session lifecycle:** Sessions are created on first use (no explicit creation API). They accumulate exposure facts until explicitly closed via `broker.close_session(session_id)` or until a configurable TTL expires (default: 24 hours). Expired sessions are archived to the audit log and their working memory facts are retracted.

### Exposure Facts

Every successful data access within a session asserts an exposure fact into CLIPS working memory:

```yaml
# templates/exposure.yaml
templates:
  - name: session_exposure
    slots:
      - name: session_id
        type: string
        required: true
      - name: agent_id
        type: string
        required: true
      - name: source_id
        type: string
        required: true
      - name: data_types_accessed
        type: multifield
        required: true
      - name: classification
        type: symbol
        required: true
      - name: fields_returned
        type: multifield
      - name: record_count
        type: integer
      - name: timestamp
        type: float
      - name: query_hash
        type: string

  - name: session_exposure_summary
    slots:
      - name: session_id
        type: string
        required: true
      - name: cumulative_classification
        type: symbol
      - name: data_types_accessed
        type: multifield
      - name: sources_accessed
        type: multifield
      - name: unique_agents
        type: multifield
      - name: exposure_flags
        type: multifield
```

### Exposure Policy Rules

Policy rules evaluate cumulative exposure on every request within a session. These rules fire *before* routing rules and can deny or restrict subsequent access based on what has already been accessed.

```yaml
# rules/policy/exposure.yaml
ruleset: exposure-policy
module: policy
version: 1.0

rules:
  - name: classification-escalation-detection
    description: "Detect when combining data from two sources produces a higher effective classification"
    salience: 100
    when:
      session_exposure:
        session_id: $session
        data_types_accessed: contains("pii")
      session_exposure:
        session_id: $session
        data_types_accessed: contains("financial")
      not:
        exposure_flag:
          session_id: $session
          flag: "pii-financial-combination"
    then:
      action: assert
      fact:
        template: exposure_flag
        slots:
          session_id: $session
          flag: "pii-financial-combination"
          severity: high
          description: "Session combines PII and financial data — effective classification escalated"
          detected_at: (now)
      action: modify
      fact: session_exposure_summary
      slots:
        cumulative_classification: escalate_one_level
      log: full

  - name: block-escalated-session-from-additional-pii
    description: "Once a session has a classification escalation flag, deny further PII access"
    salience: 200
    when:
      exposure_flag:
        session_id: $session
        flag: "pii-financial-combination"
      intent:
        session_id: $session
        data_types_needed: contains("pii")
    then:
      action: deny_request
      reason: "Session has accumulated PII + financial data. Further PII access denied pending review."
      remediation: "Start a new session or request human authorization override."
      log: full

  - name: cross-agent-exposure-alert
    description: "Alert when data accessed by agent A appears in a session where agent B is now querying"
    salience: 100
    when:
      session_exposure:
        session_id: $session
        agent_id: $agent_a
        data_types_accessed: contains("pii")
      intent:
        session_id: $session
        agent_id: $agent_b
        constraint: "$agent_b != $agent_a"
    then:
      action: assert
      fact:
        template: exposure_flag
        slots:
          session_id: $session
          flag: "cross-agent-pii-propagation"
          severity: medium
          description: "Agent {$agent_b} is querying in a session where Agent {$agent_a} accessed PII"
      log: full
```

### What Exposure Tracking Does Not Do (v1)

v1 exposure tracking operates within declared sessions. It cannot detect exposure propagation that occurs *outside* Nautilus — for example, if Agent A writes PII-derived content to a shared file that Agent B later reads independently. Cross-system exposure tracking requires integration with the agent orchestration layer and is a v2 concern (see Cross-Agent Information Flow Tracking).

v1 also cannot retroactively evaluate exposure for requests that have already been served. It is forward-looking: once an exposure flag is raised, it affects *subsequent* requests in the session, not past ones.

---

## Fathom DSL

Nautilus rules are authored in YAML and compiled to CLIPS constructs by Fathom (`fathom-rules` on PyPI). Fathom is a standalone rules DSL that Nautilus depends on as its interface to the CLIPS inference engine.

The YAML rule syntax shown throughout this document is not pseudocode — it is the actual Fathom DSL. Fathom compiles these YAML definitions into CLIPS `defrule`, `deftemplate`, `deffunction`, and `deffacts` constructs, which are then loaded into the CLIPS environment via `clipspy`.

### What Fathom Handles

Fathom provides: YAML-to-CLIPS compilation, template validation (type checking on slots before compilation), rule conflict detection at compile time (duplicate rule names, contradictory salience assignments within the same module), and a module system that maps to CLIPS modules for namespace isolation.

### What Fathom Does Not Handle

Fathom compiles individual rules correctly. It does not currently perform cross-rule semantic analysis — it cannot detect that Rule A and Rule B, when fired in sequence, produce a logical contradiction in working memory. This is a known limitation and is addressed in the Rule Conflict Detection section below.

### Compilation Example

```yaml
# Input: Fathom YAML
rules:
  - name: route-to-nvd
    when:
      intent:
        data_types_needed: contains("cve")
    then:
      action: assert
      fact:
        template: routing_decision
        slots:
          source: "nvd_db"
          decision: allow
```

```clips
; Output: Compiled CLIPS
(defrule route-to-nvd
   (intent (data_types_needed $? "cve" $?))
   =>
   (assert (routing_decision (source "nvd_db") (decision allow))))
```

---

## Routing and Policy Engine

When a request arrives, the broker translates intent into CLIPS facts and runs the engine. Rules fire in salience order within modules. The module execution order is fixed: `policy` → `routing` → `transformation` (v1), with `suggestions` added in v2.

### Module Execution Order

```
Request arrives
      │
      ▼
┌─────────────┐
│   policy     │  Salience: 100-200
│              │  Evaluates: clearance, purpose, exposure state
│              │  Can: deny request, restrict scope, flag exposure
│              │  Fail behavior: deny (fail-closed)
└──────┬──────┘
       │ (if not denied)
       ▼
┌─────────────┐
│   routing    │  Salience: 0-99
│              │  Evaluates: data types, source capabilities, relationships
│              │  Can: select sources, set scope constraints
│              │  Fail behavior: return empty with explanation
└──────┬──────┘
       │
       ▼
┌─────────────┐
│transformation│  Salience: -1 to -19
│              │  Evaluates: routing decisions, clearance
│              │  Can: redact fields, aggregate, normalize
│              │  Fail behavior: return unmodified data
└──────┬──────┘
       │
       ▼ (v2 only)
┌─────────────┐
│ suggestions  │  Salience: -20 to -99
│              │  Evaluates: routing decisions, relationship facts, affinities
│              │  Can: suggest additional sources/data types
│              │  Fail behavior: no suggestions (non-blocking)
└─────────────┘
```

### Fail-Closed Semantics

"Fail-closed" is stated as a design principle. Here is how it is mechanically enforced:

1. **No routing decision = deny.** If no routing rule fires for a given data type, the broker does not query any source for that type. The response includes the unrouted type in `sources_skipped` with reason `"no-matching-rule"`.

2. **Policy deny overrides routing allow.** Policy rules fire at higher salience. A `deny_request` action in the policy module sets a fact that the routing module checks before asserting any `routing_decision`. If the deny is scoped to a specific source or data type, only that source/type is blocked.

3. **Adapter failure = source excluded.** If a query adapter throws an exception or times out, the source is excluded from the response. The response includes the source in a new `sources_failed` field with the error class (not the raw error, which may contain sensitive information).

4. **Intent analysis failure = structured error.** If the intent analyzer cannot extract any data types with confidence above the configurable threshold (default: 0.5), the request is not forwarded to the engine. The broker returns a structured error prompting the agent to use a structured request.

---

## Result Synthesis

When routing selects multiple sources, their results must be merged into a single response. The synthesizer is the component that does this. In v1, it is deliberately simple.

### v1 Synthesis Strategy

The v1 synthesizer performs structured merging — it does not attempt semantic deduplication or intelligent fusion. It returns results grouped by source with metadata:

```python
response.data = {
    "nvd_db": {
        "records": [...],
        "record_count": 12,
        "query_duration_ms": 45,
        "scope_applied": {"cve_id": "CVE-2026-1234"}
    },
    "internal_vulns": {
        "records": [...],
        "record_count": 3,
        "query_duration_ms": 120,
        "scope_applied": {"cve_id": "CVE-2026-1234", "classification": "<=cui"}
    }
}
```

The calling agent is responsible for interpreting and merging results across sources. Nautilus provides the routing, scoping, and policy enforcement — it does not (in v1) make semantic judgments about how to combine a Postgres row with an Elasticsearch document.

### Why Not Smarter Synthesis in v1

Semantic synthesis — deduplication, conflict resolution, cross-source joins — requires understanding the schema and semantics of each source's data. This understanding is exactly what the Retentive Knowledge Model (v2) builds over time. Attempting smart synthesis in v1 would require either hard-coded schema knowledge (fragile) or LLM inference at query time (violates the core thesis). v1 defers to the agent.

### v2 Synthesis Enhancements

v2 adds transformation rules that fire after query execution. These rules can: redact fields that exceed the agent's clearance from otherwise-accessible records, aggregate raw records into summaries when the agent's purpose doesn't require granularity, resolve conflicts when multiple sources return contradicting information (via source precedence rules), and normalize formats across sources (dates, identifiers, naming conventions). Transformation rules are authored in the Fathom DSL and participate in the same audit trail as routing and policy rules.

---

## Retentive Knowledge Model (v2)

The Retentive Knowledge Model (RKM) is what separates Nautilus from every GraphRAG system, knowledge graph, and data routing tool. The name reflects the system's architecture: a rules-based expert system that is structurally and functionally equivalent to a neural network (per Hruska et al., 1991), retaining learned knowledge as certainty factors and relationship facts that persist and refine over time. The system gets smarter through four mechanisms — all governed by rules, not by probabilistic inference at query time. **All RKM features are v2.**

### 1. Meta-Rules (Rules That Write Rules)

CLIPS supports rules that assert new rules. Nautilus uses this for automated relationship discovery based on patterns it observes.

```yaml
# rules/meta/pattern-tracker.yaml
ruleset: pattern-tracker
module: curator
version: 1.0

rules:
  - name: track-sequential-requests
    description: "When agents consistently request data type A followed by data type B, record a potential relationship"
    when:
      access_log:
        agent_id: $agent
        data_type: $type_a
        timestamp: $t1
      access_log:
        agent_id: $agent
        data_type: $type_b
        timestamp: $t2
        constraint: "$t2 - $t1 < 300"
      not:
        source_relationship:
          data_type_a: $type_a
          data_type_b: $type_b
    then:
      action: assert
      fact:
        template: relationship_candidate
        slots:
          data_type_a: $type_a
          data_type_b: $type_b
          observation_count: 1
          first_observed: $t1
      log: summary

  - name: strengthen-relationship-candidate
    description: "Increment observation count when the same pattern is seen again"
    when:
      relationship_candidate:
        data_type_a: $type_a
        data_type_b: $type_b
        observation_count: $count
      access_log:
        data_type: $type_a
      access_log:
        data_type: $type_b
    then:
      action: modify
      fact: relationship_candidate
      slots:
        observation_count: ($count + 1)

  - name: promote-high-confidence-relationship
    description: "Auto-generate a routing suggestion rule when pattern is observed 10+ times"
    salience: -10
    when:
      relationship_candidate:
        data_type_a: $type_a
        data_type_b: $type_b
        observation_count: greater_than(9)
    then:
      action: propose_rule
      rule:
        name: "auto-suggest-{$type_a}-with-{$type_b}"
        module: suggestions
        description: "Auto-discovered: agents requesting {$type_a} frequently also need {$type_b}"
        when:
          intent:
            data_types_needed: contains($type_a)
            data_types_needed: not_contains($type_b)
        then:
          action: suggest_addition
          data_type: $type_b
          reason: "Agents requesting {$type_a} also needed {$type_b} in {observation_count} of last sessions"
          confidence: high
      validation: sandbox
      log: full

  - name: flag-low-confidence-for-human
    description: "Queue ambiguous patterns for human review"
    salience: -10
    when:
      relationship_candidate:
        data_type_a: $type_a
        data_type_b: $type_b
        observation_count: between(3, 9)
    then:
      action: queue_for_review
      message: "Potential relationship detected: {$type_a} → {$type_b} (observed {observation_count} times). Confirm or dismiss."
      log: summary
```

The pattern: observe → count → auto-promote high-confidence relationships → flag ambiguous ones for humans. Fully deterministic. Every auto-generated rule has a traceable lineage back to the observations that created it.

### 2. LLM as Knowledge Engineer (Maintenance-Time Only)

Periodically (configurable — hourly, daily, on-demand), Nautilus feeds recent request patterns to an LLM and asks it to suggest new rules. These suggestions enter the validation pipeline — they never execute directly.

```python
class KnowledgeEngineer:
    def suggest_rules(self, recent_requests, existing_rules, source_registry):
        prompt = f"""
        Given these recent agent requests:
        {recent_requests}

        And these existing routing rules:
        {existing_rules}

        And these available data sources:
        {source_registry}

        Suggest new YAML routing rules that would improve:
        1. Source selection accuracy
        2. Proactive suggestions for related data
        3. Similarity groupings between data types

        Output valid Fathom YAML rule format only.
        """
        suggestions = llm.generate(prompt)
        return self.parse_and_validate(suggestions)
```

The LLM does the creative, fuzzy, pattern-recognition work. But its output is a *rule proposal*, not a runtime decision. The rule goes through validation before it can fire. At runtime, CLIPS executes deterministically on approved rules only.

For air-gapped environments, the LLM knowledge engineer is disabled. Meta-rules, expert network learning, and human authoring handle knowledge retention instead.

### 3. Fuzzy Similarity Scoring (via Deffunctions)

FuzzyCLIPS is unmaintained and incompatible with current clipspy. Instead, Nautilus implements fuzzy-like scoring as custom CLIPS deffunctions within standard CLIPS.

```yaml
# functions/similarity.yaml
functions:
  - name: similarity_score
    description: "Compute weighted similarity between two data type sets based on co-occurrence history"
    params: [type_set_a, type_set_b]
    # Computes Jaccard-like similarity weighted by co-occurrence frequency
    # Returns 0.0-1.0 confidence score
    # Backed by relationship facts in working memory

  - name: relevance_threshold
    description: "Returns true if similarity_score exceeds configurable threshold"
    params: [type_set_a, type_set_b, threshold]

  - name: freshness_weight
    description: "Decay function — recent observations weigh more than old ones"
    params: [timestamp, half_life_seconds]
```

This gives auditable, traceable similarity scores. "I suggested this because it has 0.82 similarity to your last three requests based on these membership functions" — every number traces to a rule and a set of observations.

### 4. Expert Networks (Automated Certainty Factor Refinement)

Hruska, Kuncicky, and Lacher (1991) demonstrated that CLIPS rule bases can be structurally mapped onto a special class of neural networks called expert networks. In this mapping, rules of the form `if A then B (cf)` become network nodes — an assertion node for A connected to an assertion node for B, with the certainty factor as the connection weight. Conjunction and negation in rule antecedents are handled via special operator nodes with fixed weights. When activated with input, the expert network functions identically to the CLIPS inference engine operating on the same rule base.

The critical insight is that once rules are in network form, connectionist learning algorithms — specifically Expert System Backpropagation and Goal-Directed Monte Carlo Search — can automatically refine the certainty factors using training data. For Nautilus, this training data already exists: the audit log records every request, every routing decision, and every outcome (success, denial, agent retry, exposure flag). This is a labeled dataset.

**How this fits Nautilus:**

The three existing RKM mechanisms each address a different level of knowledge acquisition:
- **Meta-rules** discover structural patterns (new relationships between data types)
- **LLM knowledge engineer** proposes new rules (new routing logic, new suggestions)
- **Fuzzy similarity scoring** provides confidence values for affinity-based suggestions

Expert Networks address a fourth level: **refining the confidence values on existing rules**. A routing rule might say "if the agent requests vulnerability data and has incident-response purpose, route to the internal_vulns source with confidence 0.85." But is 0.85 the right confidence? The rule was authored by a human or promoted by a meta-rule with a heuristic score. Expert Network training can derive the optimal confidence from observed outcomes.

**The refinement cycle:**

```
┌─────────────────────────────────────────────────────────┐
│  1. Export current CLIPS rule base                       │
│                                                         │
│  2. Parse rules into expert network structure            │
│     - Assertion nodes for facts                          │
│     - Operator nodes for conjunction/negation            │
│     - Connection weights = certainty factors             │
│                                                         │
│  3. Extract training data from audit log                 │
│     - Input: request facts (intent, clearance, purpose)  │
│     - Desired output: correct routing decisions          │
│       (derived from: no agent retry, no exposure flag,   │
│        no human override within N minutes of response)   │
│                                                         │
│  4. Run learning algorithm                               │
│     - Expert System Backpropagation for gradient descent │
│       on certainty factors                               │
│     - Smoothed thresholding function (Traphan & Lacher)  │
│       enables differentiability across full value range  │
│                                                         │
│  5. Map refined weights back to CLIPS certainty factors  │
│                                                         │
│  6. Proposed changes enter validation pipeline            │
│     - Same sandbox, confidence scoring, promotion flow   │
│     - Change type: "expert-network-refinement"           │
│     - Human review if any certainty factor shifts > 0.2  │
└─────────────────────────────────────────────────────────┘
```

**What counts as "correct" training output:** This is the key design decision. Nautilus defines a successful routing decision as one where: the agent did not immediately retry with a rephrased request (indicating the initial routing missed relevant sources), no exposure flag was raised that required session termination (indicating policy was too permissive), and no human operator overrode the decision within a configurable window (default: 30 minutes). Unsuccessful decisions provide the error signal for backpropagation.

**Scope constraints:** Expert Network refinement modifies certainty factors only — it does not add, remove, or restructure rules. Rule structure changes remain the domain of meta-rules and the LLM knowledge engineer. This separation is important: the network topology is fixed during training (it mirrors the rule base), and only connection weights change. This bounds the impact of any single refinement cycle and makes changes easy to audit ("rule X's confidence changed from 0.72 to 0.81 based on 500 training examples").

**Relationship to FuzzyCLIPS:** The original paper used EMYCIN-style certainty factors, which CLIPS does not natively support. FuzzyCLIPS would have provided this, but it is unmaintained. Nautilus instead implements certainty factors as slot values on fact templates (the `confidence` slot on `routing_decision`, `source_relationship`, and `data_type_affinity` facts). The expert network parser maps these slot values to connection weights. The Fathom DSL's `declare` block could be extended to support a `certainty` field, mirroring the original CLIPS research prototype.

```yaml
# Example: Fathom rule with explicit certainty factor
rules:
  - name: route-vuln-to-internal
    declare:
      certainty: 0.85
    when:
      intent:
        data_types_needed: contains("vulnerability")
        purpose: "incident-response"
    then:
      action: assert
      fact:
        template: routing_decision
        slots:
          source: "internal_vulns"
          decision: allow
          confidence: $certainty
```

**Implementation timing:** Expert Networks are a late v2 feature. Prerequisites: stable rule base with sufficient audit log history (minimum ~1000 labeled decisions for meaningful training), the Fathom `certainty` declaration, and the expert network parser (CLIPS-to-network translation). The learning algorithms themselves are well-documented in the literature. The parser is the primary engineering effort.

**Reference:** Hruska, S.I., Dalke, A., Ferguson, J.J., and Lacher, R.C. (1991). "Expert Networks in CLIPS." NASA Conference Publication 10090, NASA Johnson Space Center.

---

## Rule Conflict Detection and Validation Pipeline (v2)

Auto-generated rules (from meta-rules or LLM suggestions) never go directly into production. They pass through a validation pipeline. This section specifies what that pipeline actually does, because "check for conflicts" is not a specification.

### The Conflict Problem

Rule conflict in a RETE network is not simply two rules with contradictory conclusions. It manifests in several forms:

**Direct contradiction:** Rule A asserts `(routing_decision (source "x") (decision allow))` while Rule B asserts `(routing_decision (source "x") (decision deny))` for the same request. CLIPS will assert both facts. The broker must have a resolution strategy.

**Cascade failure:** Rule A creates a fact that triggers Rule B, which creates a fact that triggers Rule C, which retracts the fact that Rule A depends on, causing a retraction cascade. This is particularly dangerous with meta-rules that write new rules — a self-modifying system can create cycles.

**Shadow rules:** A new rule has conditions that are a strict subset of an existing rule's conditions. The new rule fires for every case the old rule fires, plus additional cases. This may be intentional (refinement) or accidental (the LLM engineer didn't know about the existing rule).

**Salience inversion:** A new rule with higher salience than an existing rule changes the effective behavior of the existing rule by modifying facts before the existing rule evaluates them.

### Validation Pipeline

```
Rule Proposed (from meta-rule or LLM engineer)
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  Stage 1: Static Analysis                                │
│                                                         │
│  Performed by Fathom at compile time:                    │
│  - Syntax validation (does the YAML compile to CLIPS?)   │
│  - Template validation (do referenced slots exist?)      │
│  - Duplicate detection (name collision with existing?)   │
│  - Module scoping (does it reference facts from modules  │
│    it shouldn't see?)                                    │
│                                                         │
│  Reject on: compilation failure, template mismatch,      │
│  unauthorized module reference                           │
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│  Stage 2: Shadow and Subsumption Check                   │
│                                                         │
│  Compare the new rule's LHS (conditions) against all     │
│  existing rules in the same module:                      │
│  - Is the new rule's LHS a subset of an existing rule?   │
│    (shadow — flag for review)                            │
│  - Is an existing rule's LHS a subset of the new rule?   │
│    (subsumption — the new rule may obsolete the old one) │
│  - Does the new rule modify facts that appear in the LHS │
│    of rules with lower salience? (cascade risk)          │
│                                                         │
│  This analysis operates on the compiled CLIPS constructs │
│  and is necessarily conservative — it flags potential     │
│  conflicts rather than proving them.                     │
│                                                         │
│  Reject on: nothing. Flag for human review if risks found│
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│  Stage 3: Sandbox Execution                              │
│                                                         │
│  Load the new rule into an isolated CLIPS environment    │
│  alongside the current production rule set. Replay the   │
│  last N requests (configurable, default: 1000) from the  │
│  audit log as facts.                                     │
│                                                         │
│  Measure:                                                │
│  - Did any previously-allowed request get denied?        │
│    (regression — automatic reject)                       │
│  - Did any previously-denied request get allowed?        │
│    (policy relaxation — flag for human review)           │
│  - Did the rule fire at all? (dead rule — flag)          │
│  - What is the average working memory size delta?        │
│    (memory growth — flag if >5% increase)                │
│  - Did any retraction cascade exceed depth 3?            │
│    (cascade risk — flag for human review)                │
│                                                         │
│  Reject on: regression (previously-allowed now denied)   │
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│  Stage 4: Confidence Scoring                             │
│                                                         │
│  Score based on sandbox results:                         │
│  - High (>0.9): no flags, fired for >10% of replayed    │
│    requests, no regressions → auto-promote               │
│  - Medium (0.6-0.9): minor flags or low fire rate        │
│    → queue for human review                              │
│  - Low (<0.6): significant flags or regressions          │
│    → reject with explanation                             │
│                                                         │
│  Confidence formula:                                     │
│  base = 1.0                                              │
│  - 0.3 per regression detected                           │
│  - 0.2 per policy relaxation detected                    │
│  - 0.1 per shadow/subsumption flag                       │
│  - 0.1 if fire rate < 5% of replayed requests            │
│  - 0.05 per cascade depth warning                        │
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│  Stage 5: Promotion or Review                            │
│                                                         │
│  High confidence → auto-promote to production rule set.  │
│  Rule metadata recorded: proposer, timestamp, sandbox    │
│  results, confidence score, promotion method (auto).     │
│                                                         │
│  Medium confidence → enters human review queue.          │
│  Reviewer sees: the rule, sandbox results, all flags,    │
│  the requests that triggered the rule in sandbox, and    │
│  the proposed effect on routing decisions.               │
│                                                         │
│  Low confidence → rejected. Rejection reason recorded.   │
│  If proposed by meta-rule, the originating meta-rule's   │
│  observation count is not reset (it may re-propose after │
│  further observations).                                  │
└─────────────────────────────────────────────────────────┘
```

### Rule Rollback

Every promoted rule receives a version number and a timestamp. If a production issue is traced to a specific rule (via the routing trace in the response), the rule can be retracted:

```bash
nautilus rule retract auto-suggest-vulnerability-with-patch --reason "caused false denials for compliance agents"
```

Retraction removes the rule from the active CLIPS environment and marks it as `retired` in the persistence layer. It does not delete the rule — retired rules are preserved for lineage tracking.

When a rule is retracted, Nautilus identifies all rules that were proposed *because* of the retracted rule (via lineage metadata) and flags them for re-evaluation. This prevents orphaned rules whose justification has been invalidated.

### Direct Contradiction Resolution

For the specific case of contradictory routing decisions (allow vs. deny for the same source), Nautilus applies a fixed precedence: **deny always wins**. If multiple rules produce conflicting routing decisions, the most restrictive decision is applied and all firing rules are recorded in the routing trace. This is not configurable — it is a consequence of fail-closed design.

---

## Relationships as Facts

Nautilus doesn't use a graph database. Relationships between data sources, data types, and agents are represented as CLIPS facts in working memory. The RETE algorithm pattern-matches across them the same way it matches against any other fact.

```yaml
# templates/relationships.yaml
templates:
  - name: source_relationship
    description: "A discovered or declared relationship between data sources"
    slots:
      - name: source_a
        type: string
        required: true
      - name: source_b
        type: string
        required: true
      - name: relationship_type
        type: symbol
        allowed_values: [overlaps, supplements, contradicts, feeds_into, derived_from]
      - name: field
        type: string
      - name: confidence
        type: float
      - name: discovered_by
        type: string
      - name: timestamp
        type: float
      - name: status
        type: symbol
        allowed_values: [active, proposed, retired]

  - name: data_type_affinity
    description: "Observed co-occurrence pattern between data types"
    slots:
      - name: type_a
        type: string
      - name: type_b
        type: string
      - name: strength
        type: float
      - name: observation_count
        type: integer
      - name: last_observed
        type: float
```

At runtime, when Nautilus routes a request, rules pattern-match against these relationship facts to find related sources and data types. The "graph" is implicit in working memory — no graph database needed for traversal because RETE already indexes facts for fast pattern matching.

In v1, relationship facts are manually authored. In v2, new relationship facts get asserted by meta-rules, the LLM knowledge engineer, or human operators, and their certainty factors are refined by expert network learning. Old relationships decay via freshness_weight functions. The knowledge landscape evolves as facts are asserted, modified, and retracted.

---

## Proactive Suggestions (v2)

The librarian doesn't just fetch what was asked — it knows the collection well enough to say "you probably also need this."

Suggestion rules fire during the same evaluation cycle as routing rules, using relationship facts and affinity scores:

```yaml
# rules/suggestions.yaml
ruleset: suggestions
module: suggestions
version: 1.0

rules:
  - name: suggest-related-data-types
    description: "Suggest data types with high affinity to what was requested"
    salience: -20
    when:
      intent:
        data_types_needed: contains($type_a)
      data_type_affinity:
        type_a: $type_a
        type_b: $type_b
        strength: greater_than(0.7)
      not:
        intent:
          data_types_needed: contains($type_b)
    then:
      action: suggest_addition
      data_type: $type_b
      reason: "High affinity ({strength}) with requested type '{$type_a}'"
      log: summary

  - name: suggest-overlapping-source
    description: "When a denied source overlaps with an allowed source, suggest the allowed one"
    salience: -20
    when:
      routing_decision:
        source: $denied_source
        decision: deny
      source_relationship:
        source_a: $denied_source
        source_b: $alt_source
        relationship_type: overlaps
      routing_decision:
        source: $alt_source
        decision: allow
    then:
      action: suggest_alternative
      original: $denied_source
      alternative: $alt_source
      reason: "'{$alt_source}' contains overlapping data and is within your clearance"
      log: summary
```

---

## Persistence Architecture

CLIPS working memory is the runtime representation of everything Nautilus knows. But CLIPS has no native persistence — when the process stops, working memory dies. Nautilus uses dumb storage underneath for durability.

```
┌─────────────────────────────────────────────┐
│        CLIPS Working Memory (Runtime)       │
│                                             │
│  Facts: source metadata, relationships,     │
│         affinities, access logs, session    │
│         state, relationship candidates,     │
│         routing decisions, exposure state   │
│                                             │
│  Rules: routing, policy, transformation,    │
│         (v2: suggestions, meta-rules,       │
│          auto-generated rules)              │
│                                             │
│  RETE network indexes all of this for       │
│  sub-millisecond pattern matching           │
└──────────────┬──────────────────────────────┘
               │ serialize on shutdown
               │ deserialize on startup
               │
┌──────────────▼──────────────────────────────┐
│     Persistence Layer (Dumb Storage)        │
│                                             │
│  Production: PostgreSQL                     │
│  - Serialized facts (JSONB)                 │
│  - Rule definitions (YAML + compiled CLIPS) │
│  - Template definitions                     │
│  - Audit log (append-only)                  │
│  - Source registry config                   │
│  - Session exposure state                   │
│  - (v2) Rule proposal queue                 │
│  - (v2) Rule lineage metadata               │
│                                             │
│  Single-node / air-gapped: SQLite           │
│  - Same schema, zero operational overhead   │
│  - Ships as a single file                   │
└─────────────────────────────────────────────┘
```

The persistence layer is explicitly dumb. It doesn't do relationship traversal or query routing — CLIPS does that in memory. Postgres/SQLite just ensures nothing is lost on restart.

Neo4j is not in the architecture. If graph visualization is needed for an admin UI, it can be generated from serialized relationship facts in Postgres. A live graph database would create a sync problem — two representations of the same knowledge — with no runtime benefit since CLIPS handles all traversal via RETE.

### Startup and Deserialization Cost

Deserializing working memory on startup is not free. For a deployment with 5,000 facts and 200 rules, initial RETE network construction and fact assertion takes approximately 1-3 seconds (benchmarking required). For larger deployments (50,000+ facts), startup may take 10-30 seconds. This is acceptable for a service that is expected to run continuously, but it means Nautilus is not suitable for serverless/lambda deployment patterns where cold start latency matters.

v1 mitigates this by supporting a health check endpoint that returns `ready` only after deserialization completes. Orchestrators (Kubernetes, ECS) should gate traffic behind this check.

---

## Concurrency Model

CLIPS is single-threaded. The RETE network, working memory, and rule execution are not thread-safe. Nautilus must handle concurrent agent requests without corrupting CLIPS state.

### v1 Approach: Request Serialization with Async I/O

v1 uses a single CLIPS instance with serialized access. Requests are queued and processed one at a time through the CLIPS engine. However, the expensive part of most requests is not CLIPS evaluation (sub-millisecond) but adapter query execution (network I/O). The request lifecycle is:

1. **Acquire CLIPS lock.** Assert intent facts, run engine, collect routing decisions. Release lock. (~1ms)
2. **Execute adapter queries concurrently.** All selected adapters run in parallel via asyncio. (~50-500ms depending on sources)
3. **Acquire CLIPS lock.** Assert exposure facts, run transformation rules, collect results. Release lock. (~1ms)

The CLIPS lock is held for ~2ms per request. At 500 concurrent requests, the worst-case queue depth for CLIPS access is manageable. The bottleneck is adapter I/O, which is fully parallel.

### v2 Approach: Blackboard Architecture

For deployments where CLIPS lock contention becomes measurable, v2 introduces the Blackboard pattern with domain-specialized workers (see Scaling Architecture).

---

## Failure Modes and Recovery

### Corrupted Working Memory

**Cause:** A meta-rule (v2) or manual rule asserts facts that cause an unexpected retraction cascade, leaving working memory in an inconsistent state — for example, session exposure facts retracted mid-evaluation.

**Detection:** After each engine run, Nautilus performs a consistency check: are all required session facts still present? Do all routing decisions reference valid sources? If the check fails, the engine run is rolled back by retracting all facts asserted during that run and the request is denied with a `system-error` reason.

**Recovery:** The audit log records the pre-run fact snapshot (as a list of fact identifiers). On consistency failure, the snapshot is used to restore working memory to its pre-run state. The offending request is logged with full context for debugging.

**Prevention:** v2 meta-rules are restricted to asserting facts in the `curator` module. They cannot modify or retract facts in the `policy` or `routing` modules. This module isolation is enforced by Fathom at compile time.

### Adapter Failure

**Cause:** A data source is unreachable, times out, or returns an error.

**Behavior:** The adapter is excluded from results. The response includes the source in `sources_failed` with error class and timing. Other sources are unaffected — adapter queries are independent.

**Retry:** v1 does not retry. The calling agent can retry the full request. v2 may add configurable per-adapter retry with exponential backoff, but this is not committed.

### Persistence Failure

**Cause:** Postgres/SQLite is unreachable when Nautilus attempts to write the audit log or serialize session state.

**Behavior:** Nautilus continues serving requests from working memory. Audit log entries are buffered in-memory (bounded queue, default 10,000 entries). When persistence recovers, the buffer is flushed. If the buffer fills, the oldest entries are dropped and a warning is logged.

**Risk:** If Nautilus crashes while the buffer is full and persistence is down, audit log entries are lost. This is an accepted risk for v1. v2 may add a write-ahead log to local disk as a secondary buffer.

### Classification Leak via LLM-Generated Rule (v2)

**Cause:** The LLM knowledge engineer proposes a rule that passes sandbox validation but causes a subtle policy violation in production — for example, a suggestion rule that effectively reveals the *existence* of a classified source to an uncleared agent by suggesting it.

**Detection:** Suggestion rules include the source name in their output. A post-evaluation policy check (a rule in the `policy` module with salience -100, firing after suggestions) validates that every suggested source is within the agent's clearance. Suggestions referencing sources above the agent's clearance are silently dropped.

**Prevention:** The LLM knowledge engineer's prompt includes the classification hierarchy and a constraint that suggested rules must not reference specific source names — only data types. Source resolution happens at routing time within the policy module.

### Session State Loss

**Cause:** Nautilus restarts mid-session. Working memory is lost. The session's exposure facts are gone.

**Recovery:** On startup, Nautilus deserializes the last-persisted session state from the database. Sessions are persisted after every request (the exposure fact assertion step includes a persistence write). The worst case is loss of the *current* request's exposure update if Nautilus crashes between CLIPS assertion and persistence write. This means one request's worth of exposure tracking may be lost on crash — the session will continue with the previous exposure state.

**Mitigation:** The persistence write is synchronous by default. An async mode is available for higher throughput at the cost of this one-request-loss window.

---

## Attestation and Audit

### Attestation Token

Every response includes a signed attestation token — a JWT containing: the request hash, the routing trace hash, the list of sources queried and denied, the cumulative exposure state, and a timestamp. The token is signed with a configurable key (HMAC-SHA256 by default, RS256 for environments requiring asymmetric signing).

**Who holds the keys?** The Nautilus instance holds the signing key. In multi-instance deployments (v2 Blackboard), each worker holds the same key (distributed via secrets management — Vault, K8s secrets, etc.). Key rotation is supported via a `nautilus key rotate` command that generates a new key and re-signs active session tokens.

**Verification:** Any system with the public key (or shared secret) can verify the attestation. This is intended for downstream audit systems, compliance tools, or the Bosun governance layer.

### Audit Log

The audit log is append-only and records every request, every routing decision, every policy evaluation, every exposure fact, and (in v2) every rule proposal and promotion. It is the forensic record of everything Nautilus has done.

The audit log is stored in Postgres (or SQLite) and is queryable via SQL. v2 adds a REST API for audit queries and an admin UI for browsing the trail.

**Retention:** Configurable. Default: 90 days. Archived entries are exported to a configurable sink (S3, local filesystem) before deletion.

---

## Adapter Security Model

Adapters execute scoped queries against data sources. Scope enforcement is the mechanism by which Nautilus restricts what an adapter can return. This section addresses the security implications.

### WHERE Clause Injection (Postgres Adapter)

The Postgres adapter applies scope constraints by injecting WHERE clauses into queries. This is SQL injection-adjacent by design — the adapter is constructing SQL dynamically.

**Mitigations:**

1. **Parameterized queries only.** Scope constraints are always applied via parameterized queries, never string concatenation. The adapter uses `psycopg`'s parameter binding exclusively.

2. **Allowlisted columns.** Each source in the registry declares which columns can appear in scope constraints. The adapter rejects scope constraints referencing columns not in the allowlist.

3. **No raw SQL.** The routing engine produces scope constraints as structured objects (`{"field": "asset_type", "operator": "IN", "values": ["server", "network_device"]}`), not SQL strings. The adapter translates these to parameterized SQL.

4. **Read-only connections.** All adapter connections are configured with read-only database users. Even if a constraint is somehow malformed, it cannot modify data.

### REST API Adapter

The REST adapter applies scope as parameter constraints and endpoint allowlisting. Each source declares allowed endpoints and allowed parameter values. The adapter rejects any request that targets an endpoint or parameter not in the allowlist.

---

## Source Registry

```yaml
# nautilus.yaml
sources:
  - id: nvd_db
    type: postgres
    description: "National Vulnerability Database mirror"
    classification: unclassified
    data_types: [cve, vulnerability, patch]
    allowed_columns: [cve_id, description, severity, published_date, affected_product]
    connection: ${NVD_DB_URL}

  - id: internal_vulns
    type: pgvector
    description: "Internal vulnerability assessments and scan results"
    classification: cui
    data_types: [vulnerability, scan_result, remediation]
    allowed_purposes: [threat-analysis, compliance-audit]
    connection: ${INTERNAL_VULN_URL}

  - id: cmdb
    type: servicenow
    description: "Configuration Management Database"
    classification: cui
    data_types: [asset, configuration, relationship]
    allowed_purposes: [threat-analysis, asset-management, incident-response]
    connection: ${SNOW_INSTANCE_URL}

  - id: hr_records
    type: postgres
    description: "Human resources personnel data"
    classification: pii
    data_types: [employee, role, clearance]
    allowed_purposes: [hr-operations, insider-threat]
    allowed_columns: [employee_id, department, role, clearance_level]
    connection: ${HR_DB_URL}

  - id: threat_intel
    type: rest_api
    description: "External threat intelligence feed"
    classification: unclassified
    data_types: [ioc, threat_actor, campaign]
    allowed_endpoints: [/indicators, /actors, /campaigns]
    connection: ${THREAT_INTEL_API}
    rate_limit: 100/hour
```

---

## Classification Hierarchy

```yaml
# classification.yaml
hierarchy:
  - level: unclassified
    rank: 0
  - level: cui
    rank: 1
    sub_categories: [cui-sp-cti, cui-sp-prvcy, cui-sp-tax]
  - level: confidential
    rank: 2
  - level: secret
    rank: 3
  - level: top-secret
    rank: 4
    compartments: [sci-a, sci-b, sci-c]

custom_hierarchy:
  - level: public
    rank: 0
  - level: internal
    rank: 1
  - level: confidential
    rank: 2
  - level: restricted
    rank: 3
```

---

## Agent Interface

### Python SDK

```python
from nautilus import Broker

broker = Broker.from_config("nautilus.yaml")

# Natural language request
response = broker.request(
    agent_id="agent-alpha",
    intent="What systems are affected by CVE-2026-1234?",
    context={"clearance": "secret", "purpose": "incident-response"}
)

# Structured request (skip intent analysis)
response = broker.query(
    agent_id="agent-alpha",
    data_types=["vulnerability", "asset"],
    filters={"cve_id": "CVE-2026-1234"},
    context={"clearance": "secret", "purpose": "incident-response"}
)

# Close a session
broker.close_session("incident-response-42")
```

### REST API

```
POST /v1/request
{
    "agent_id": "agent-alpha",
    "intent": "What systems are affected by CVE-2026-1234?",
    "context": {
        "clearance": "secret",
        "purpose": "incident-response"
    }
}

Response:
{
    "data": { ... },
    "suggestions": [],
    "sources_queried": ["nvd_db", "internal_vulns", "cmdb"],
    "sources_denied": ["hr_records"],
    "sources_skipped": ["marketing_db"],
    "sources_failed": [],
    "routing_trace": [ ... ],
    "exposure_summary": {
        "session_id": "sess-001",
        "cumulative_classification": "cui",
        "data_types_accessed": ["cve", "vulnerability", "asset"],
        "exposure_flags": []
    },
    "attestation_token": "eyJhbG...",
    "duration_ms": 230
}
```

### MCP Tool

```python
from nautilus.integrations.mcp import NautilusMCPServer

server = NautilusMCPServer(broker)
server.serve()
```

---

## Query Executors (Adapters)

### v1

| Source Type | Adapter | Scope Enforcement |
|-------------|---------|-------------------|
| PostgreSQL | `nautilus.adapters.postgres` | Parameterized WHERE clause injection, column filtering, allowlisted columns |
| pgvector | `nautilus.adapters.pgvector` | Metadata filtering on similarity search |

### v2

| Source Type | Adapter | Scope Enforcement |
|-------------|---------|-------------------|
| Elasticsearch | `nautilus.adapters.elastic` | Query DSL filter injection |
| REST API | `nautilus.adapters.rest` | Parameter constraints, endpoint allowlisting |
| ServiceNow | `nautilus.adapters.servicenow` | GlideRecord encoded query scoping, ACL passthrough |
| S3/Document Store | `nautilus.adapters.documents` | Prefix/tag-based access, classification label filtering |

### Custom Adapters

```python
from nautilus.adapters import BaseAdapter

class MyAdapter(BaseAdapter):
    source_type = "my_database"

    def connect(self, config):
        ...

    def execute(self, query_intent, scope_constraints):
        ...

    def apply_scope(self, base_query, constraints):
        ...

    def health_check(self) -> bool:
        ...
```

---

## Deployment Models

### Standalone (development/small teams)

```bash
uv add nautilus-broker
nautilus serve --config nautilus.yaml
```

Uses SQLite by default. Single process, single CLIPS instance.

### Container (production)

```bash
docker run -p 8080:8080 \
  -v ./config:/config \
  -v ./rules:/rules \
  -e DATABASE_URL=postgres://... \
  kraken/nautilus:latest
```

### Air-gapped (classified environments, v2)

```bash
nautilus serve --config nautilus.yaml --air-gapped
```

Air-gapped mode disables: LLM knowledge engineer, external API adapters, telemetry. Enables: pattern-matching intent analyzer, meta-rules-only knowledge retention, SQLite persistence. All data stays local. Container image available for offline registries.

---

## Scaling Architecture (v2)

CLIPS RETE performance degrades as working memory grows beyond tens of thousands of facts. For large deployments, Nautilus uses a Blackboard architecture with specialized workers.

```
┌──────────────────────────────────────────────────┐
│                  Coordinator                      │
│  Routes requests to appropriate specialist        │
│  Merges results from multiple specialists         │
│  Maintains global session state                   │
└───────┬──────────┬──────────┬────────────────────┘
        │          │          │
   ┌────▼───┐ ┌───▼────┐ ┌───▼────┐
   │Worker A│ │Worker B│ │Worker C│
   │        │ │        │ │        │
   │Security│ │Business│ │  Ops   │
   │sources │ │sources │ │sources │
   │        │ │        │ │        │
   │Own CLIPS│ │Own CLIPS│ │Own CLIPS│
   │instance│ │instance│ │instance│
   │        │ │        │ │        │
   │Bounded │ │Bounded │ │Bounded │
   │working │ │working │ │working │
   │memory  │ │memory  │ │memory  │
   └────────┘ └────────┘ └────────┘
```

Each worker maintains CLIPS expertise over a bounded domain. Working memory stays small per worker. RETE stays fast. The coordinator handles cross-domain requests by querying multiple workers and merging results.

Cross-worker relationship facts live in the coordinator's CLIPS instance, enabling cross-domain pattern discovery without blowing up any single worker's memory.

This is a v2 concern. Single-instance CLIPS handles v1 deployment scale.

---

## Observability

### v1 Metrics

Nautilus exposes Prometheus-compatible metrics at `/metrics`:

- `nautilus_requests_total` — counter by agent_id, purpose, outcome (success/denied/error)
- `nautilus_clips_evaluation_ms` — histogram of CLIPS engine run duration
- `nautilus_adapter_query_ms` — histogram by adapter type and source_id
- `nautilus_adapter_errors_total` — counter by adapter type and error class
- `nautilus_session_exposure_flags_total` — counter by flag type
- `nautilus_working_memory_facts` — gauge of current fact count
- `nautilus_clips_lock_wait_ms` — histogram of time spent waiting for CLIPS lock

### v2 Metrics

- `nautilus_rule_proposals_total` — counter by proposer (meta-rule, llm-engineer, human)
- `nautilus_rule_promotions_total` — counter by promotion method (auto, human)
- `nautilus_rule_rejections_total` — counter by rejection reason
- `nautilus_sandbox_evaluation_ms` — histogram of sandbox run duration

### Structured Logging

All log entries include: request_id, session_id, agent_id, and a trace_id that correlates with the routing trace in the response. Log format is JSON for machine parsing.

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