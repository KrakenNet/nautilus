# CLI Reference

Nautilus provides a CLI via `nautilus` (or `python -m nautilus`).

## `nautilus serve`

Start the broker transport.

```
nautilus serve --config nautilus.yaml [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `nautilus.yaml` | Path to configuration file |
| `--transport` | `rest` | Transport mode: `rest`, `mcp`, or `both` |
| `--mcp-mode` | `stdio` | MCP transport when `mcp`/`both`: `stdio` or `http` |
| `--bind` | `127.0.0.1:8000` | Bind address for REST transport |
| `--air-gapped` | — | Force pattern analyzer, refuse LLM providers, drop non-loopback LLM sources |
| `--log-format` | `text` | Application log format: `text` or `json` |

## `nautilus health`

Probe a running instance.

```
nautilus health --url http://localhost:8000/readyz
```

## `nautilus version`

Print the installed version.

```
nautilus version
```

## `nautilus key`

Session-token signing-key management — see
[key rotation in the operator guide](../how-to/operator-guide.md#6-rotate-signing-keys).

```
nautilus key list [--json]
nautilus key rotate [--remove-old] --yes [--json]
nautilus key revoke <kid> --reason TEXT --yes [--json]
```

## `nautilus rules`

Rule validation and testing — see [Authoring Rules](../how-to/authoring-rules.md).

```
nautilus rules validate FILE [--sandbox] [--replay-n N] [--json]
nautilus rules test --file FILE [--audit-log PATH] [--threshold 0.6] [--json]
nautilus rules history --module M [--json]
```

`rules test` exit codes: `0` pass, `1` validation/regression failure,
`2` below confidence threshold.

## `nautilus adapters`

Adapter registry, scaffolding, and schema-drift operations — see
[Developing Adapters](../how-to/developing-adapters.md).

```
nautilus adapters list [--status S] [--json]
nautilus adapters new NAME [--dir PATH]
nautilus adapters schema NAME [--json]
nautilus adapters schema-fingerprint NAME
nautilus adapters schema-diff NAME [--json]
nautilus adapters schema-ack NAME --reason TEXT --yes
```

## `nautilus attestation`

Offline verification of chained attestation logs — see
[Verify a token](../how-to/verify-a-token.md).

```
nautilus attestation verify LOG [--pubkey PEM] [--expected-head HASH] [--anchor-token JWS] [--json]
```

## `nautilus rkm` / `nautilus rule`

Review-queue and rule-lifecycle management — see
[RKM: the Rule Lifecycle](../concepts/rkm-lifecycle.md).

```
nautilus rkm queue list|show|diff|approve|reject ...
nautilus rkm lineage
nautilus rule list|retract|lineage|history|rollback ...
```

## `nautilus events`

```
nautilus events list [--json]
```

Enumerate the audit `event_type` vocabulary.
