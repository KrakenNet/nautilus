# The Trust Boundary

What Nautilus assumes, what it enforces, and what it cannot see. Every
guarantee on the other pages — classification dominance, purpose limitation,
cumulative-exposure escalation, the signed receipt — rests on the three
conditions below. They are deployment properties, not code properties: nothing
in Nautilus can check them for you.

## 1. Nautilus is the sole enforcement point

The broker decides what an agent may read *because it is the only path to the
data*. An agent that can open its own connection to a source is not governed
by anything Nautilus does; the decision, the denial and the attestation
describe a request it did not have to make.

So the boundary is a network boundary, not an API convention:

- Source credentials live only in the broker's environment. An agent that
  holds the DSN can bypass every rule with one `psql`.
- The sources are reachable only by the broker — a private subnet, a security
  group that admits the broker's task role and nothing else, a Unix socket, a
  database user whose `pg_hba.conf` entry names the broker's host. **The DSN
  must be reachable only by the broker**, and that is enforced by the network,
  not by this project.
- Every agent path to the data terminates at `/v1/request`, the MCP tool, or
  the library API. If a second path exists, it is the deployment's real
  policy.

The corollary: a Nautilus deployment is a control on *agents*, not on the
humans who operate it. An operator with shell access to the broker host can
read anything the broker can read. What they cannot do is make that invisible
— the audit log and, with `audit.chained: true`, its hash chain are the
control on the operator.

## 2. Source credentials are service credentials

The credential in `sources[].auth` (or in the DSN) is **the broker's**
credential for that system, not a per-agent one. Nautilus does not impersonate
the calling agent downstream, and no adapter forwards an agent identity to a
source.

That has three consequences worth stating plainly:

- **The source sees one client.** Row-level security, database roles and
  per-user quotas in the source apply to the broker, uniformly. Per-agent
  restriction is Nautilus's job — clearance, compartments, purpose, and the
  scope constraints rules attach — and it happens before the query is issued,
  not inside the source.
- **The credential should be least-privilege for the whole deployment.** Grant
  it exactly the tables, indices, buckets or endpoints that the declared
  sources name. A read-only role is the common case; anything Nautilus is not
  configured to read, the credential should not be able to read.
- **Rotation is an operator action, on the source's schedule.** Nautilus reads
  `${VAR}` interpolations at startup, so rotating means updating the secret
  store and restarting (or rolling) the broker. Config errors never print the
  resolved value, so a failed rotation does not put the new secret in the
  startup logs.

The agent's identity is carried in the *decision*, not in the connection: the
audit entry's `principal_id`, the attestation token's binding to the
authenticated caller, and the exposure ledger's derived principal are where
"who asked" lives. See
[Bind a credential to an agent](../how-to/operator-guide.md#bind-a-credential-to-an-agent).

## 3. One deployment is one tenant

The agent registry, the exposure ledger, the signing key ring and the loaded
rule set are all deployment-wide. Two agents in one deployment are separated
by policy — clearance, compartments, purpose, and rules — and not by
isolation: they share a ruleset, a set of source credentials and one audit
log an operator reads as a single stream.

That is the right shape for one organization's agents over one organization's
data. It is not a shape to serve two customers from. A second tenant means a
second deployment: its own config, its own source credentials, its own audit
log and its own key ring. Replicas scale a deployment *out*, not *across* —
see [Running more than one replica](../how-to/operator-guide.md#running-more-than-one-replica).

## What Nautilus does not defend against

Stated so the gaps are chosen rather than assumed:

- **A compromised broker host.** The broker holds every source credential and
  the signing key. Host compromise is total compromise; the chained audit log
  makes it detectable after the fact, not survivable.
- **A source that lies.** Nautilus governs what is asked for and records what
  came back. It does not verify that the data is what the source claims.
- **Exfiltration after delivery.** Once a request is allowed, the rows are in
  the agent's context. Cumulative-exposure tracking bounds how much an agent
  can accumulate before escalation; it does not follow the data afterwards.
- **A caller that lies about `agent_id` with an unbound credential.** A bare
  `api.keys` string authenticates the port, not the agent — the broker warns
  about this at startup. Bind keys to agents to close it.
- **Rules that are wrong.** The engine enforces the rules it is given. RKM's
  sandbox, lineage and review path exist so a rule change is reviewable and
  reversible, not so it is correct.
