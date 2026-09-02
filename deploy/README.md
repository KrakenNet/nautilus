# Deploying Nautilus

The deployment guide is part of the published documentation set:
[docs/how-to/deploying.md](../docs/how-to/deploying.md), published at
<https://krakennet.github.io/nautilus/latest/how-to/deploying/>. It covers both
supported paths — a plain container runtime and Kubernetes — the environment,
volumes and probes they share, upgrade and rollback, and what to run inside an
image with no shell in it.

This directory holds the manifests that guide applies:

| File | Object |
|---|---|
| `configmap.yaml` | ConfigMap `nautilus-config` |
| `secret.yaml` | Secret `nautilus-secrets`, Secret `nautilus-attestation-key` |
| `deployment.yaml` | Deployment `nautilus` |
| `service.yaml` | Service `nautilus` |

None of them set `metadata.namespace`. Apply them from the repository root, in
the order [§3.3](../docs/how-to/deploying.md#33-apply-in-this-order) gives.
