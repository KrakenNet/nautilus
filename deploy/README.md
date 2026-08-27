# Deploying Nautilus on Kubernetes

A minimal, complete manifest set: one Deployment, one Service, the config as a
ConfigMap, and every credential in Secrets.

```bash
docker build -t nautilus:latest .          # from the repository root
kubectl apply -f deploy/
kubectl port-forward svc/nautilus 8000:8000
curl -H "X-API-Key: $NAUTILUS_API_KEY" -X POST localhost:8000/v1/request \
  -d '{"agent_id": "support-bot", "intent": "recent orders", "context": {"purpose": "support"}}'
```

## What to change before you apply this

- **`secret.yaml`** — every value is `replace-me`. Generate the API key
  (`openssl rand -hex 32`) and the attestation key (`nautilus key generate`),
  and keep both out of git; this file is a shape, not a store.
- **`configmap.yaml`** — the `sources` block. It points at Postgres; swap in
  the type that matches your data, or `type: static` to serve rows declared in
  the config while you are wiring things up.
- **`deployment.yaml`** — the image reference, and the `audit` volume. It is an
  `emptyDir` here so the example runs anywhere, which means the audit log dies
  with the pod. Use a PersistentVolumeClaim or ship the lines to a collector.

## Why it is shaped this way

- The ConfigMap holds no credentials. Source DSNs and the API key are `${ENV}`
  references resolved from the Secret at config load, so the file you would
  paste into a ticket has nothing in it.
- `readOnlyRootFilesystem: true` with explicit writable mounts for the key
  ring and the audit log — the broker writes nowhere else.
- `/readyz` is the readiness probe, not `/healthz`: it fails when the session
  store or the audit sink is unwritable, which is exactly when a replica must
  stop taking requests.
- One replica by default. Scaling out needs shared state — see
  [Running more than one replica](../docs/how-to/operator-guide.md#running-more-than-one-replica),
  and note that one deployment is one tenant.
