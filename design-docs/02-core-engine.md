# Nautilus — Core Engine

> *Part 2 of 5 — Exposure tracking, Fathom DSL, routing/policy, synthesis. See also:* [01-overview](./01-overview.md) · [03-living-brain](./03-living-brain.md) · [04-architecture-operations](./04-architecture-operations.md) · [05-ecosystem-roadmap](./05-ecosystem-roadmap.md)

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
