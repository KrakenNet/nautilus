# Nautilus — The Living Brain

> *Part 3 of 5 — Knowledge evolution, rule validation, relationships, suggestions (all v2). See also:* [01-overview](./01-overview.md) · [02-core-engine](./02-core-engine.md) · [04-architecture-operations](./04-architecture-operations.md) · [05-ecosystem-roadmap](./05-ecosystem-roadmap.md)

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
