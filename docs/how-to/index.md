# How-to Guides

Task-oriented guides for common Nautilus operations.

## Guides

- [Operator Guide](operator-guide.md) — deploy end to end: install,
  configure, serve, monitor, rotate keys, back up audit.
- [Deploying](deploying.md) — run the broker in a container: the image, the
  host layout, the Kubernetes manifests, environment, volumes, probes, upgrade
  and rollback, and every procedure that has to work in an image with no shell.
- [Authoring Rules](authoring-rules.md) — the rule DSL, salience, the
  denial-record invariant, and the validate → test → ship workflow.
- [Developing Adapters](developing-adapters.md) — scaffold a package,
  pass the compliance suite, load via entry point or local path.
- [Hardening](hardening.md) — the complete security surface, key by key: every
  security-relevant config key, environment variable, header, CLI flag and
  route, each with what it defends, what it costs, the exact string it emits
  when set wrong, and a runnable example; plus TLS termination, key rotation,
  a failure-string index and one hardened end-to-end configuration.

## Recipes

- [Add a Postgres source](add-a-postgres-source.md)
- [Write a routing rule](write-a-routing-rule.md)
- [Configure attestation](configure-attestation.md)
- [Verify a token](verify-a-token.md)
- [Add an LLM source](add-an-llm-source.md)
- [Monitor with Grafana](monitor-with-grafana.md)
