# Deploying Nautilus

Two supported ways to run the broker in production: a plain container runtime
(`docker` / `podman`) and Kubernetes. Both run the same image, the same
`nautilus.yaml`, the same four mounts and the same two probes. Pick one; the
rest of this file — environment, volumes, probes, upgrade, rollback,
troubleshooting, and [what to run inside a container with no shell in
it](#11-working-inside-a-distroless-container) — applies to both.

Files in this directory:

| File | Object | Purpose |
|---|---|---|
| `configmap.yaml` | ConfigMap `nautilus-config` | the broker's `nautilus.yaml`, mounted at `/config` |
| `secret.yaml` | Secret `nautilus-secrets`, Secret `nautilus-attestation-key` | the API key, the source DSNs, the Ed25519 signing key |
| `deployment.yaml` | Deployment `nautilus` | one pod, four mounts, two probes |
| `service.yaml` | Service `nautilus` | ClusterIP, port 8000 |

None of the manifests set `metadata.namespace`, so `-n <ns>` on every command
decides where they land. Everything below uses `-n nautilus`.

---

## 1. The image

Built from the repository `Dockerfile` (repo root), which has three stages:

| Stage | Base | Built by default | Use |
|---|---|---|---|
| `builder` | `ghcr.io/astral-sh/uv:python3.14-bookworm-slim` | yes (intermediate) | resolves `uv.lock` into `/app/.venv` |
| `debug` | `python:3.14-slim` | no — `--target debug` | same tree, plus `bash`; operator-local only |
| `runtime` | `gcr.io/distroless/cc-debian13` | yes — last stage, so a bare `docker build .` selects it | what you ship |

Properties of the `runtime` image you have to design around:

- **No shell, no package manager, no `pip`.** You cannot install anything into
  a built image. `kubectl exec -it … -- sh` will fail with
  `exec: "sh": executable file not found in $PATH`. Every operational procedure
  in this documentation set has a form that works anyway —
  [§11](#11-working-inside-a-distroless-container). The `debug` stage is for
  reproducing a problem on your laptop, not for diagnosing a running pod:
  swapping the image is a new rollout, so the state you wanted to look at is
  gone before the shell exists.
- **`ENTRYPOINT ["/app/.venv/bin/python", "-m", "nautilus"]`**, so any
  `args:` / trailing `docker run` arguments are `nautilus` subcommand
  arguments, not a command line.
- **`CMD ["serve", "--config", "/config/nautilus.yaml", "--bind", "0.0.0.0:8000"]`.**
  `nautilus serve` defaults to `127.0.0.1:8000`, which inside a container means
  "serve nobody"; the explicit `--bind` is what makes the port reachable.
- **`USER 65532:65532`** (distroless `nonroot`). Every writable path you mount
  must be writable by UID 65532.
- **`HEALTHCHECK … CMD ["/app/.venv/bin/python", "-m", "nautilus", "health"]`**,
  every 30s, 5s timeout, 10s start period, 3 retries. `nautilus health` GETs
  `http://localhost:8000/readyz` and exits 0 only on HTTP 200.
- **No database drivers.** The default build installs `--extra otel` and
  nothing else.

### Build it

```bash
cd /path/to/nautilus                      # repository root, where Dockerfile lives

# Default image — no adapter drivers. Enough for `type: static` and
# `type: rest` sources and a sqlite/memory session store.
docker build -t nautilus:0.2.6.dev0 .

# What the manifests in this directory need: configmap.yaml declares a
# `postgres` source and `session_store.backend: postgres`, and asyncpg is an
# optional extra.
docker build \
  --build-arg EXTRAS="--extra postgres" \
  --build-arg BUILD_REV="$(git rev-parse HEAD)$(git diff --quiet || echo -dirty)" \
  -t nautilus:0.2.6.dev0-postgres .
```

`BUILD_REV` is what a running container answers `GET /healthz` with, and it is
the only thing that separates two images built from the same release line —
`0.2.6.dev0` is shared by every commit between two releases, by design.
`.dockerignore` excludes `.git/`, so no layer can work the revision out for
itself and it has to be passed in. **Omit it and the image answers
`"build": "unknown"`** — deliberately, rather than repeating the version and
looking like a real answer. The build is not refused: an sdist has no revision
to give.

`EXTRAS` is passed verbatim to `uv sync`. Available extras (from
`pyproject.toml`): `postgres`, `pgvector`, `elasticsearch`, `neo4j`,
`influxdb`, `s3`, `all`. Combine them:
`--build-arg EXTRAS="--extra postgres --extra s3"`.

Skipping this is the single most common first failure — see
[the driver error](#the-pod-crashloops-immediately) below.

Verify what you built:

```bash
docker run --rm nautilus:0.2.6.dev0-postgres version
# 0.2.6.dev0
# build: 6b2879595e642133a8a04ba184659a8a8389d336-dirty
```

Line 1 is the release line, line 2 the revision, so `… version | head -1` still
gives the bare version. On the distroless runtime image this is the only way to
ask which build you are holding without starting it: there is no shell in it.

---

## 2. Path A — plain container runtime

No Kubernetes. One host, one container, bind mounts instead of volumes.

### 2.1 Lay out the host directories

```bash
sudo mkdir -p /srv/nautilus/{config,keys,state,audit}

# The Ed25519 key attestations are signed with. `nautilus key` operates on a
# *running* broker's ring (list / rotate / revoke), so it cannot mint this one.
sudo openssl genpkey -algorithm ed25519 -out /srv/nautilus/keys/attestation.pem
sudo chmod 0400 /srv/nautilus/keys/attestation.pem

# The container runs as UID 65532 and writes to state/ and audit/.
sudo chown -R 65532:65532 /srv/nautilus/keys /srv/nautilus/state /srv/nautilus/audit
```

### 2.2 Write the config

Take it straight out of `configmap.yaml` — the `data["nautilus.yaml"]` block is
a complete config:

```bash
# Run from the repository root. Needs PyYAML on the host (pip install pyyaml);
# copying the block out of configmap.yaml by hand and de-indenting it by four
# spaces gives the identical file.
python3 -c 'import yaml,sys; sys.stdout.write(yaml.safe_load(open("deploy/configmap.yaml"))["data"]["nautilus.yaml"])' \
  > /tmp/nautilus.yaml
sudo install -m 0444 /tmp/nautilus.yaml /srv/nautilus/config/nautilus.yaml
```

Single-host installs usually do not want a Postgres session store. Swap that
one block for a durable local one — it survives restarts and needs no server:

```yaml
session_store:
  backend: sqlite
  sqlite_path: /var/lib/nautilus/sessions.db   # on the writable `state` mount
  ttl_seconds: 3600
```

With that change `SESSION_DSN` is no longer referenced and can be dropped from
the environment. `backend: memory` also exists and loses every session — and
therefore every cumulative exposure total — on restart.

### 2.3 Run it

```bash
export NAUTILUS_API_KEY="$(openssl rand -hex 32)"   # keep it; callers need it

docker run -d \
  --name nautilus \
  --restart unless-stopped \
  --user 65532:65532 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 8000:8000 \
  -e NAUTILUS_API_KEY \
  -e ORDERS_DSN="postgresql://nautilus:secret@10.0.0.5:5432/orders" \
  -e SESSION_DSN="postgresql://nautilus:secret@10.0.0.5:5432/sessions" \
  -v /srv/nautilus/config/nautilus.yaml:/config/nautilus.yaml:ro \
  -v /srv/nautilus/keys/attestation.pem:/etc/nautilus/keys/attestation.pem:ro \
  -v /srv/nautilus/state:/var/lib/nautilus \
  -v /srv/nautilus/audit:/var/log/nautilus \
  nautilus:0.2.6.dev0-postgres \
  serve --config /config/nautilus.yaml --bind 0.0.0.0:8000 --log-format json
```

Notes on the flags that are not obvious:

- `--read-only` mirrors the Kubernetes `readOnlyRootFilesystem: true`. The four
  bind mounts are the only paths the broker writes.
- `--tmpfs /tmp` is needed only if you pass `--air-gapped`, which rewrites the
  config through `tempfile.NamedTemporaryFile`. Harmless otherwise.
- The trailing `serve …` replaces the image `CMD`; the `ENTRYPOINT` still
  supplies `python -m nautilus`.
- `-p 8000:8000` maps host 8000 to the container's 8000. Change only the left
  half; the right half must match `--bind`.

### 2.4 Confirm it came up

```bash
docker ps --filter name=nautilus --format '{{.Names}}\t{{.Status}}'
# nautilus	Up 42 seconds (healthy)
```

`(healthy)` is the image's own `HEALTHCHECK` reporting a 200 from `/readyz`.
`(unhealthy)` after ~40s means readiness never went green — go to
[§10 Troubleshooting](#10-troubleshooting).

```bash
curl -fsS localhost:8000/healthz;  echo
# {"status":"ok","version":"0.2.6.dev0","build":"6b2879595e642133a8a04ba184659a8a8389d336-dirty"}

curl -fsS localhost:8000/readyz;   echo
# {"status":"ok"}

docker logs nautilus | tail -5
# {"levelname": "INFO", "name": "uvicorn.error", "message": "Application startup complete."}
# {"levelname": "INFO", "name": "uvicorn.error", "message": "Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)"}
```

(`--log-format json` produces those one-JSON-object-per-line records; drop it
or pass `--log-format text` for human-readable logs.)

Then the real thing — [§7 Reaching it](#7-reaching-the-broker).

---

## 3. Path B — Kubernetes

### 3.1 Make the image reachable from the cluster

`deployment.yaml` sets `imagePullPolicy: IfNotPresent` and an image with no
registry prefix, so the tag has to already exist on the node. Pick one:

```bash
# kind
kind load docker-image nautilus:0.2.6.dev0-postgres --name <cluster>

# minikube
minikube image load nautilus:0.2.6.dev0-postgres

# a real cluster: push, then edit deployment.yaml's `image:` to match
docker tag nautilus:0.2.6.dev0-postgres registry.example.com/nautilus:0.2.6.dev0-postgres
docker push registry.example.com/nautilus:0.2.6.dev0-postgres
```

### 3.2 Fill in the Secrets

`secret.yaml` ships placeholders (`replace-me`) and is a *shape*, not a store —
`stringData` is plaintext. Generate real values and create the Secrets outside
git:

```bash
kubectl create namespace nautilus

kubectl -n nautilus create secret generic nautilus-secrets \
  --from-literal=NAUTILUS_API_KEY="$(openssl rand -hex 32)" \
  --from-literal=ORDERS_DSN='postgresql://nautilus:secret@postgres:5432/orders' \
  --from-literal=SESSION_DSN='postgresql://nautilus:secret@postgres:5432/sessions'

openssl genpkey -algorithm ed25519 -out attestation.pem
kubectl -n nautilus create secret generic nautilus-attestation-key \
  --from-file=attestation.pem=./attestation.pem
rm attestation.pem
```

If you would rather keep the manifest, replace every `replace-me` in
`secret.yaml` and run it through sealed-secrets / External Secrets / SOPS
before committing anything.

### 3.3 Apply, in this order

```bash
kubectl -n nautilus apply -f deploy/configmap.yaml
kubectl -n nautilus apply -f deploy/secret.yaml      # skip if you used `create secret` above
kubectl -n nautilus apply -f deploy/deployment.yaml
kubectl -n nautilus apply -f deploy/service.yaml
```

`kubectl apply -f deploy/` applies all four at once and is fine — the pod
restarts on its own if the ConfigMap or Secret lands a moment later.

### 3.4 Confirm it came up

```bash
kubectl -n nautilus rollout status deployment/nautilus --timeout=180s
# Waiting for deployment "nautilus" rollout to finish: 0 of 1 updated replicas are available...
# deployment "nautilus" successfully rolled out

kubectl -n nautilus get pods -l app.kubernetes.io/name=nautilus
# NAME                        READY   STATUS    RESTARTS   AGE
# nautilus-7d9c5f4b8c-2xk4p   1/1     Running   0          38s
```

`READY 1/1` means `/readyz` returned 200. `0/1` with `STATUS Running` means the
process is alive and readiness is failing — read the probe body, not the pod
list:

```bash
kubectl -n nautilus exec deploy/nautilus -- /app/.venv/bin/python -m nautilus health
# OK 200 http://localhost:8000/readyz
```

(That works on the distroless image because it invokes the interpreter
directly. `-- sh -c …` does not; there is no shell.)

```bash
kubectl -n nautilus port-forward svc/nautilus 8000:8000 &
curl -fsS localhost:8000/readyz; echo
# {"status":"ok"}
```

---

## 4. Environment variables

Everything the container reads. `envFrom.secretRef: nautilus-secrets` injects
the whole Secret, so every key you put in that Secret becomes an environment
variable; only the ones a `${VAR}` in `nautilus.yaml` references are actually
used. A `${VAR}` with no matching variable is a **startup failure**, not a
warning: `nautilus/config/loader.py` raises
`Missing env var 'X' referenced by source id='…'`.

| Variable | Required | Read by | Meaning |
|---|---|---|---|
| `NAUTILUS_API_KEY` | yes, as shipped | `${NAUTILUS_API_KEY}` in `api.keys` | the value callers send as `X-API-Key`. Generate: `openssl rand -hex 32`. An empty `api.keys` fails closed — every data and governance route answers 401 |
| `ORDERS_DSN` | yes, as shipped | `${ORDERS_DSN}` in `sources[0].connection` | Postgres DSN for the `orders` source. Rename/remove it with the source |
| `SESSION_DSN` | yes, as shipped | `${SESSION_DSN}` in `session_store.dsn` | Postgres DSN for the session store. Unused if you set `backend: sqlite` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | `nautilus/observability/instrumentation.py` | turns **trace export** on. Unset, the broker still creates spans and still serves every `nautilus_*` series on `/metrics` — it just exports nothing. e.g. `http://otel-collector.observability:4318` |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | no | same | traces-only variant; either one enables the exporter |
| `OTEL_SDK_DISABLED` | no | `nautilus/observability/__init__.py` | `true` skips instrumentation entirely. This also removes the Prometheus reader, so `/metrics` loses every `nautilus_*` series. Use the endpoint variables to control export instead |
| `OTEL_PYTHON_FASTAPI_EXCLUDED_URLS` | no | same file | defaulted to `/healthz,/readyz` so probes are not traced. Override to trace them |
| `TEST_PG_DSN` | no | `nautilus/core/broker.py` | fallback for `session_store.dsn` when `backend: postgres` and no `dsn` is set. Prefer `dsn: ${SESSION_DSN}` |
| `INFLUXDB_V2_TOKEN`, `INFLUXDB_V2_ORG` | only with an `influxdb` source | `nautilus/adapters/influxdb.py` | token/org when the source config carries no `auth_token` |
| `NAUTILUS_REVIEWER` | no | `nautilus/cli/_common.py` | identity stamped on `nautilus rkm` approvals. Irrelevant to `serve` |
| `PYTHONPATH=/app`, `PATH=/app/.venv/bin:$PATH`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUNBUFFERED=1` | baked in | `Dockerfile` `runtime` stage | do not override. `PYTHONDONTWRITEBYTECODE` is what makes a read-only root filesystem work; `PYTHONUNBUFFERED` is what makes logs appear before a crash |

An LLM analysis provider reads whatever variable `analysis.provider.api_key_env`
names (`nautilus/analysis/llm/*_provider.py`) — nothing is read unless you
configure one.

### `serve` flags the manifest passes

`deployment.yaml` sets
`args: ["serve", "--config", "/config/nautilus.yaml", "--bind", "0.0.0.0:8000", "--log-format", "json"]`.

| Flag | Default | Notes |
|---|---|---|
| `--config` | `./nautilus.yaml` | must match the ConfigMap mount path |
| `--bind HOST:PORT` | `api.host`/`api.port` from the config, else `127.0.0.1:8000` | overrides the config. Must be `0.0.0.0` in a container |
| `--log-format` | `text` | `json` for SIEM-ingestable lines on stdout |
| `--transport` | `rest` | `mcp` or `both`; with `both` and `--mcp-mode http`, MCP binds `PORT + 1` (8001) — add a second `containerPort` and Service port for it |
| `--mcp-mode` | `stdio` | `http` when serving MCP over a socket |
| `--air-gapped` | off | forces `analysis.mode: pattern` and drops non-loopback `type: llm` sources, printing a `WARN:` line per override |

---

## 5. Volumes and mounts

| Mount path | Volume | Source | Mode | What it holds | What happens without it |
|---|---|---|---|---|---|
| `/config` | `config` | ConfigMap `nautilus-config` | read-only | `nautilus.yaml` | `ERROR: config path does not exist or is not a file: /config/nautilus.yaml`, exit 2, CrashLoopBackOff |
| `/etc/nautilus/keys` | `attestation-key` | Secret `nautilus-attestation-key` | read-only | `attestation.pem`, the Ed25519 key from `attestation.private_key_path` | `ERROR: broker construction failed: [Errno 2] No such file or directory: '/etc/nautilus/keys/attestation.pem'`, exit 2 — `attestation.enabled: true` reads the key at construction |
| `/var/lib/nautilus` | `state` | `emptyDir`, `sizeLimit: 512Mi` | **read-write** | `keyring.json` (`session_tokens.key_ring_path`) and the schema-drift baselines (`state_dir`) | the broker tries to write under the read-only `/config` mount and under a `readOnlyRootFilesystem`; session tokens cannot be signed |
| `/var/log/nautilus` | `audit` | `emptyDir`, `sizeLimit: 2Gi` | **read-write** | `audit.jsonl` (`audit.path`) — one line per decision | `/readyz` returns 503 `{"status":"not_ready","reason":"audit log directory /var/log/nautilus is not writable"}` and the pod never becomes ready. It does not serve unrecorded requests |

Both writable volumes are `emptyDir`, which means **their contents die with the
pod**. That is deliberate for an example you can apply anywhere, and wrong for
anything you rely on:

- `audit` — the record of every decision the broker made. Replace with a
  PersistentVolumeClaim, or ship the lines to a collector (a sidecar tailing
  `/var/log/nautilus/audit.jsonl` works, since the mount is shareable).
- `state` — losing `keyring.json` invalidates every session token already
  issued: the next request presenting one fails the session-provenance gate
  closed. Losing the drift baselines just makes the next schema comparison
  re-learn from scratch.

Keep each `emptyDir` `sizeLimit` at or under `resources.limits.ephemeral-storage`
(4Gi). `emptyDir` counts against the pod's ephemeral storage; exceeding the pod
limit evicts the pod, exceeding the node's free space is a node condition and
evicts the neighbours too.

---

## 6. Probes

| | Liveness | Readiness |
|---|---|---|
| Endpoint | `GET /healthz` | `GET /readyz` |
| Healthy | `200 {"status":"ok","version":"…","build":"…"}` — see [`GET /healthz`](../docs/reference/rest-api.md#get-healthz) for what the two identifiers mean | `200 {"status":"ok"}` |
| Checks | nothing — the process answers, therefore it is alive | startup completed, **and** the audit sink is writable, **and** the session store answers a sentinel read on `_ready_probe_`, **and** the store's schema stamp still matches this build |
| `initialDelaySeconds` | 5 | 5 |
| `periodSeconds` | 30 | 10 |
| `timeoutSeconds` | 3 | 5 |
| `failureThreshold` | 3 | 3 |
| On failure | container restarted after ~95s of failures | pod removed from the Service's endpoints; the container keeps running |
| Auth | none — `/healthz`, `/readyz` and `/metrics` are the only ungated paths | none |

`timeoutSeconds: 5` on readiness is not padding: `/readyz` budgets 2.0s
(`_READY_PROBE_TIMEOUT_S`) for the sentinel read and another 2.0s for the
schema re-check. The kubelet's default `timeoutSeconds` is **1**, so a merely
slow store read as a hard failure and drained a pod that was fine.

The 503 bodies, verbatim, and what each means:

| Body | Cause | Fix |
|---|---|---|
| `{"status":"not_ready","reason":"startup_incomplete"}` | the ASGI lifespan has not finished — normal for the first seconds, permanent means startup is stuck | `kubectl logs` for the last line before it stopped |
| `{"status":"not_ready","reason":"audit log directory /var/log/nautilus does not exist"}` | the `audit` volumeMount is missing | re-apply `deployment.yaml` |
| `{"status":"not_ready","reason":"audit log directory /var/log/nautilus is not writable"}` | the volume is not writable by UID 65532 | `fsGroup: 65532` in the pod securityContext; on the docker path, `sudo chown -R 65532:65532 /srv/nautilus/audit` **on the host** ([§2.1](#21-lay-out-the-host-directories)) — there is no `chown` inside the container, and no capability that would give you one ([§11.4](#114-what-you-cannot-do-from-inside)) |
| `{"status":"not_ready","reason":"audit log /var/log/nautilus/audit.jsonl is not writable"}` | the file exists with wrong mode or wrong ownership — usually a volume first written by a root-run container | if UID 65532 owns it, `os.chmod` from inside fixes it in place; if it does not, rename it aside and let the broker create a new one. Both, measured, in [§11.3](#113-writing-renaming-and-fixing-permissions) |
| `{"status":"not_ready","reason":"session_store_timeout"}` | the store did not answer within 2.0s | Postgres is overloaded or the network path is broken; check `pool_max_size` (default 10) against your in-flight request count |
| `{"status":"not_ready","reason":"SessionStoreUnavailableError"}` | `on_failure: fail_closed` and Postgres is unreachable | fix `SESSION_DSN` / the database. This is the intended behaviour: no session store means no cumulative exposure accounting |
| `{"status":"not_ready","reason":"SessionSchemaError"}` | another Nautilus migrated the shared store to a schema version this build does not understand | finish or roll back the other rollout; `nautilus session version --dsn "$SESSION_DSN"` prints what is on disk |

Any other exception class name can appear in `reason` — it is
`type(exc).__name__` for whatever the store raised.

Neither probe is a startup probe. The liveness `initialDelaySeconds: 5` plus
`3 × 30s` gives the broker ~95 seconds to open its Postgres pool and run its
`CREATE TABLE IF NOT EXISTS` DDL before the kubelet restarts it. If your
database is slower than that to accept connections at cold start, raise
`failureThreshold` on the liveness probe rather than the delay.

---

## 7. Reaching the broker

| Where you are | Address |
|---|---|
| another pod, same namespace | `http://nautilus:8000` |
| another pod, another namespace | `http://nautilus.nautilus.svc.cluster.local:8000` |
| your laptop, via Kubernetes | `kubectl -n nautilus port-forward svc/nautilus 8000:8000` → `http://localhost:8000` |
| your laptop, docker path | `http://localhost:8000` (the `-p 8000:8000` mapping) |

The Service is `type: ClusterIP` — deliberately not internet-facing. To expose
it, put an Ingress or a Gateway in front and terminate TLS there; the broker
speaks plain HTTP. If you front it with a proxy that authenticates users, set
`api.auth.mode: proxy_trust` and `api.auth.trusted_proxies` so
`X-Forwarded-User` is honoured only from that proxy — otherwise anyone who can
reach the pod can set the header.

`service.yaml` maps `port: 8000` → `targetPort: http`, the *named* container
port. Changing the container's port name breaks the Service silently
(endpoints stay empty); changing `containerPort: 8000` without changing
`--bind` breaks nothing at all, because the number in `--bind` is what the
process actually listens on.

The one request that proves the whole path works:

```bash
curl -sS -H "X-API-Key: $NAUTILUS_API_KEY" -H 'Content-Type: application/json' \
  -X POST localhost:8000/v1/request \
  -d '{"agent_id": "support-bot", "intent": "recent orders", "context": {"purpose": "support"}}'
```

- `agent_id` must exist in the ConfigMap's `agents:` block — `support-bot` is
  the one it ships.
- `context.purpose` must be in that agent's `allowed_purposes` **and** the
  source's — `support` is in both.
- `Content-Type: application/json` is mandatory. Without it curl sends
  `application/x-www-form-urlencoded` and `/v1/request` answers `422`.
- The body is validated with `extra="forbid"`: `session_id`, `purpose` and
  `clearance` go **inside** `context`, and sending them at the top level is a
  422, not a silent drop.

A successful response is JSON with `request_id`, `data` (rows keyed by source
id), `sources_queried`, `sources_denied`, `denial_records`, `rule_trace`,
`scope_restrictions`, `attestation_token` and `duration_ms`. An empty
`data` with a populated `denial_records` is a working broker refusing — read
the `reason` and the rule id in each record.

Other responses you will see from a correctly deployed broker:

| Status | Body | Meaning |
|---|---|---|
| 401 | `{"detail":"API key required"}` | `api.keys` is empty — the broker fails closed |
| 401 | `{"detail":"Invalid API key"}` | `X-API-Key` does not match any configured key |
| 403 | `{"detail":"…"}` | the policy refused; the detail names the rule |
| 413 | `{"detail":"Request body is N bytes; this broker accepts at most 1048576 (api.max_request_bytes)."}` | raise `api.max_request_bytes` |
| 503 | `{"detail":"Broker busy: 64 requests are already in flight (api.max_concurrent_requests). Retry."}` | with `Retry-After: 1`. Saturation, not failure — the broker refuses rather than growing a queue behind the limit |

`GET /metrics` (ungated) serves the Prometheus text format, including every
`nautilus_*` series. `GET /v1/sources` lists source metadata the caller's
clearance permits — never a DSN.

---

## 8. Replicas: what actually breaks at two

`replicas: 1`, and `strategy: Recreate` so a rolling update does not
transiently produce a second pod. Both are load-bearing. With
`replicas: 2` and the manifests exactly as shipped:

1. **Session tokens stop verifying.** `session_tokens.key_ring_path` is
   `/var/lib/nautilus/keyring.json` on an `emptyDir`, so each pod mints its own
   Ed25519 ring on first boot. A token signed by pod A and presented to pod B
   fails the session-provenance gate — closed, by design. `GET /v1/keys/jwks.json`
   returns a different key set depending on which pod the Service picked.
   **Requires:** one key ring on a ReadWriteMany volume, or an external signer.
2. **The audit log splits in two.** `audit.path` is per-pod, so "every decision"
   lives in two files on two ephemeral disks, and neither is complete. Point
   both at one RWX volume and a chained attestation sink refuses the second
   writer — it takes an exclusive lock, and the pod that loses it reports the
   lock in its `/readyz` `reason` and never becomes ready.
   **Requires:** a single-writer sink, or a collector that merges both streams.
3. **Schema-drift baselines desynchronize.** `state_dir: /var/lib/nautilus`
   holds what each pod learned about source schemas. Two pods learn separately,
   so a real drift is reported twice and a rescheduled pod re-learns silently.
   **Requires:** the same RWX volume, or accept duplicate alerts.
4. **Cumulative exposure caps still hold** — this one is already fixed.
   `session_store.backend: postgres` with `dsn: ${SESSION_DSN}` puts the
   exposure ledger in a shared database, so a caller cannot dodge a cap by
   landing on the other replica. Leave it `postgres` if you scale; with
   `backend: sqlite` or `memory` each replica accounts separately and the caps
   are advisory.

So: shared session store (already), shared key ring, single audit writer,
shared state dir. Until all four hold, one replica is the correct number, and a
`Recreate` rollout is the correct upgrade. Depth on the tradeoffs:
[Running more than one replica](../docs/how-to/operator-guide.md#running-more-than-one-replica).

One deployment is also one **tenant**: the agent registry, the exposure ledger
and the signing ring are deployment-wide. A second tenant is a second
deployment, with its own namespace, Secret and database
(`docs/concepts/trust-boundary.md`).

---

## 9. Upgrade and rollback

### Kubernetes

```bash
docker build --build-arg EXTRAS="--extra postgres" -t nautilus:0.2.6-postgres .
kind load docker-image nautilus:0.2.6-postgres --name <cluster>   # or push to your registry

kubectl -n nautilus set image deployment/nautilus nautilus=nautilus:0.2.6-postgres
kubectl -n nautilus rollout status deployment/nautilus --timeout=180s
# deployment "nautilus" successfully rolled out
```

`strategy: Recreate` means the old pod is terminated *before* the new one
starts: expect a gap of a few seconds to a minute where the Service has no
endpoints and callers get connection refused. Drain callers first if that
matters.

Config-only changes cost a rollout **only when they touch a startup-only key**.
A ConfigMap edit never restarts anything on its own; what it does is change the
file under `/config`, and what happens next depends on the key.

`sources`, `rules` and the two live `session_store` limits reload in place on
`SIGHUP` — no rollout, no gap in service, which matters here because
`strategy: Recreate` at `replicas: 1` means a rollout *is* a gap:

```bash
kubectl -n nautilus apply -f deploy/configmap.yaml
# the kubelet syncs a mounted ConfigMap within ~1 minute by default
kubectl -n nautilus exec deployment/nautilus -- pkill -HUP -f 'nautilus serve'
kubectl -n nautilus logs deployment/nautilus | tail -1
# INFO:nautilus.cli.serve:SIGHUP: reloaded /config/nautilus.yaml (adopted sources, rules)
```

A refused reload leaves the running config serving and says so, so this is safe
to run against a bad edit — but it is not a substitute for checking first, and
the pod keeps serving the *old* file until you notice:

```text
ERROR:nautilus.cli.serve:SIGHUP: refused; the running config is unchanged. Reason: these keys are read once at startup and cannot be reloaded: audit. Restart the process to adopt them.
```

Everything else — `audit`, `attestation`, `session_tokens`, the rest of
`session_store`, `api`, `mcp`, `ui`, `agents`, `analysis`, `adapters`,
`state_dir`, `rkm` — is the rollout it always was, and the reload refuses it by
name rather than half-applying it
([which keys, and why](../docs/how-to/operator-guide.md#which-keys-reload-and-which-need-a-restart)):

```bash
kubectl -n nautilus apply -f deploy/configmap.yaml
kubectl -n nautilus rollout restart deployment/nautilus
kubectl -n nautilus rollout status deployment/nautilus --timeout=180s
```

Rollback:

```bash
kubectl -n nautilus rollout history deployment/nautilus
# REVISION  CHANGE-CAUSE
# 1         <none>
# 2         <none>

kubectl -n nautilus rollout undo deployment/nautilus              # previous revision
kubectl -n nautilus rollout undo deployment/nautilus --to-revision=1
kubectl -n nautilus rollout status deployment/nautilus --timeout=180s
```

`rollout undo` restores the pod template — image, args, probes, resources. It
does **not** restore the ConfigMap or the Secrets; those are separate objects
with their own history. If the upgrade included a config change, re-apply the
old `configmap.yaml` from git in the same step. It also does not migrate the
session store backwards; if the new version had stamped a new schema version,
the rolled-back pod refuses the store with `SessionSchemaError` rather than
writing rows it does not understand. Check first:

```bash
kubectl -n nautilus exec deploy/nautilus -- \
  /app/.venv/bin/python -m nautilus session version --dsn "$SESSION_DSN"
# store schema version: 1
```

### Container runtime

```bash
docker stop nautilus && docker rm nautilus
docker run -d --name nautilus … nautilus:0.2.6-postgres serve …   # §2.3, new tag
```

Rollback is the same two commands with the previous tag — which is why §1 tags
`0.2.6.dev0` (the version in `pyproject.toml`) rather than reusing `latest`. `latest` plus
`imagePullPolicy: IfNotPresent` is the classic silent no-op: the node already
has *a* `latest` and never fetches yours.

---

## 10. Troubleshooting

Start here, always:

```bash
kubectl -n nautilus get pods -l app.kubernetes.io/name=nautilus
kubectl -n nautilus describe pod -l app.kubernetes.io/name=nautilus | tail -30
kubectl -n nautilus logs deploy/nautilus --tail=50
kubectl -n nautilus logs deploy/nautilus --previous --tail=50   # the crash before the restart
```

On the docker path substitute `docker ps -a`, `docker inspect nautilus`,
`docker logs nautilus`.

### The pod CrashLoops immediately

`STATUS CrashLoopBackOff`, and `describe` shows
`Back-off restarting failed container nautilus in pod …`. The cause is the last
line of `logs --previous`. All of these are exit code 2:

| Log line | Cause | Fix |
|---|---|---|
| `ERROR: invalid config: source id='orders' has type 'postgres', whose driver is not installed: pip install 'nautilus-rkm[postgres]' (import failed: No module named 'asyncpg')` | you built the default image; the ConfigMap uses a `postgres` source | rebuild: `docker build --build-arg EXTRAS="--extra postgres" …`. You cannot `pip install` into the distroless image — that message is generic advice, not a step you can run here |
| `ERROR: invalid config: Missing env var 'ORDERS_DSN' referenced by source id='orders'` | the key is absent from Secret `nautilus-secrets` | `kubectl -n nautilus get secret nautilus-secrets -o jsonpath='{.data}' \| tr ',' '\n'` and add the missing key |
| `ERROR: config path does not exist or is not a file: /config/nautilus.yaml` | ConfigMap key is not `nautilus.yaml`, or the `config` volume did not mount | `kubectl -n nautilus get cm nautilus-config -o jsonpath='{.data}' \| head -c 200` |
| `ERROR: invalid config: session_store.backend=postgres requires 'dsn' or TEST_PG_DSN env var` | `session_store.dsn` was deleted from the ConfigMap | restore `dsn: ${SESSION_DSN}` |
| `ERROR: invalid config: Config validation failed:` followed by `  api.auth.mode: Input should be …` | a typo in `nautilus.yaml`. The rejected **value** is deliberately not printed — config values are post-interpolation by then, and printing them puts your DSN in the log | fix the field the location names |
| `ERROR: invalid config: Unsupported source type='postgress' for id='orders' (supported: [...])` | misspelled `type:` | the message lists every accepted type |
| `Application startup failed. Exiting.` preceded by `PostgresSessionStore unavailable (dsn=postgresql://nautilus:***@postgres:5432/sessions): [Errno -2] Name or service not known`, then `ERROR: application startup failed; the server never accepted a connection. The cause is logged above.` | `on_failure: fail_closed` and the database is unreachable | fix DNS/credentials/network policy. The password is redacted in that message. Exiting non-zero here is deliberate: the alternative was a pod that exited `Completed` and never restarted |
| `exec: "/app/.venv/bin/python": no such file or directory` | a hand-modified Dockerfile copied `/app` without the interpreter | rebuild from the repository `Dockerfile` |

### The pod never starts

| `describe pod` line | Cause | Fix |
|---|---|---|
| `Failed to pull image "nautilus:0.2.6.dev0-postgres": … not found`, `STATUS ErrImagePull` / `ImagePullBackOff` | the tag exists on your laptop, not on the node | §3.1 — `kind load` / `minikube image load` / push and re-tag |
| `Error: secret "nautilus-secrets" not found`, `STATUS CreateContainerConfigError` | Secret missing or in the wrong namespace | §3.2, and check `-n` |
| `Error: configmap "nautilus-config" not found` | same, for the ConfigMap | `kubectl -n nautilus apply -f deploy/configmap.yaml` |
| `0/3 nodes are available: 3 Insufficient cpu.`, `STATUS Pending` | `requests.cpu: "1"` does not fit | free capacity, or lower the request knowing the broker's per-request work is CPU-bound on one event loop |
| `0/3 nodes are available: 3 Insufficient ephemeral-storage.` | `requests.ephemeral-storage: 2Gi` does not fit | free disk, or lower the request *and* the two `emptyDir` `sizeLimit`s together |
| `violates PodSecurity "restricted:latest"` | an older copy of these manifests without `seccompProfile: RuntimeDefault` | re-apply the shipped `deployment.yaml` |
| `Multi-Attach error for volume "pvc-…" Volume is already used by pod(s) nautilus-…` | you replaced `audit` with a ReadWriteOnce PVC *and* changed `strategy` back to `RollingUpdate` | keep `strategy: Recreate`, or move to a ReadWriteMany volume |

### The pod runs but is never Ready

`READY 0/1`, `STATUS Running`, and `describe` shows
`Readiness probe failed: HTTP probe failed with statuscode: 503`. That status
code is all the kubelet reports; the reason is in the body:

```bash
kubectl -n nautilus port-forward deploy/nautilus 8000:8000 &
curl -sS -o /dev/null -w '%{http_code}\n' localhost:8000/readyz
# 503
curl -sS localhost:8000/readyz; echo
# {"status":"not_ready","reason":"audit log directory /var/log/nautilus is not writable"}
```

Look that `reason` up in [§6](#6-probes). `port-forward` works even when the
pod is not Ready — it goes to the pod, not through the Service, which is why it
is the right tool here. `kubectl get endpoints nautilus` showing
`ENDPOINTS <none>` is the same fact seen from the Service side.

### The pod restarts every couple of minutes

`RESTARTS` climbing with
`Liveness probe failed: Get "http://10.244.1.7:8000/healthz": context deadline exceeded`.
`/healthz` is a static handler with no I/O, so a timeout there means the event
loop is blocked, not that a dependency is down — the broker is CPU-saturated.
Check `container_cpu_cfs_throttled_seconds_total` and give it a full core;
`resources` deliberately sets no CPU limit for exactly this reason.

### Requests fail after a clean deploy

| Symptom | Cause |
|---|---|
| `401 {"detail":"Invalid API key"}` | `X-API-Key` does not match. The pod holds the Secret's value at the time it started — after rotating the Secret, `kubectl rollout restart` |
| `401 {"detail":"API key required"}` | `api.keys` resolved to empty. The startup log says so: `api.keys is empty, so every data and governance route will answer 401 Not authenticated. Only /healthz, /readyz and /metrics are reachable.` |
| `422` | missing `Content-Type: application/json`, or `session_id`/`purpose`/`clearance` sent at the top level instead of inside `context` |
| `200` with empty `data` and populated `denial_records` | not a deployment failure — the policy refused. Each record names the rule |
| `503 {"detail":"Broker busy: 64 requests are already in flight …"}` | concurrency limit; raise `api.max_concurrent_requests` or add capacity |
| empty `/metrics` | the image was built without `--extra otel`, or `OTEL_SDK_DISABLED=true` is set |
| `STATUS Evicted`, `The node was low on resource: ephemeral-storage.` | the audit log filled the `emptyDir`. Move `audit` to a PersistentVolumeClaim or ship the lines off-box |

### Getting a shell

There isn't one, and you do not need one:
[§11](#11-working-inside-a-distroless-container) is every procedure this
documentation set asks you to run inside a container, rewritten for an image
with no shell in it and measured against one.

---

## 11. Working inside a distroless container

There is no shell, and the rest of this documentation set assumes you know what
to run instead. `sh`, `bash`, `ls`, `cat`, `mv`, `cp`, `chmod`, `chown`, `sed`,
`tar`, `curl` and `pip` are all absent from the `runtime` image, and `exec`
reports each one identically:

```console
$ docker exec nautilus sh -c 'echo hi'
OCI runtime exec failed: exec failed: unable to start container process: exec: "sh": executable file not found in $PATH
$ docker exec nautilus ls -l /var/lib/nautilus
OCI runtime exec failed: exec failed: unable to start container process: exec: "ls": executable file not found in $PATH
$ docker exec nautilus curl -s localhost:8000/readyz
OCI runtime exec failed: exec failed: unable to start container process: exec: "curl": executable file not found in $PATH
$ docker exec nautilus pip --version
OCI runtime exec failed: exec failed: unable to start container process: exec: "pip": executable file not found in $PATH
```

The binary is absent from the image, so it is absent under every exec
transport — `kubectl exec … -- sh` has nothing to find either, and only the
wrapper text around the error differs. Every transcript in this section was
captured with `docker exec` against a container started as in
[§2.3](#23-run-it), from an image built without `BUILD_REV` and without
`--log-format json` — so the one block here that pastes a server log record,
the `SIGHUP` reload in [§11.4](#114-what-you-cannot-do-from-inside), shows the
default text form. Under §2.3's own flags that record is a JSON object
carrying the same text in `msg`, which is why the filter below matches the
message and not the line prefix. Substitute
`kubectl -n nautilus exec deploy/nautilus --` for `docker exec nautilus` and
the argv after it is unchanged.

You do not have to take a list of absences on trust. This is **every**
executable in the image, exhaustively — the `grep -v` only drops the venv's
`activate` scripts and its Windows `.bat` shims, which are not executables on
Linux:

```console
$ cid=$(docker create nautilus:0.2.6.dev0)
$ docker export "$cid" | tar -t \
    | grep -E '^(bin|sbin|usr/bin|usr/sbin|usr/local/bin|app/\.venv/bin)/[^/]+$' \
    | grep -vE 'activate|\.bat$' | sort
app/.venv/bin/dotenv
app/.venv/bin/fastapi
app/.venv/bin/fathom
app/.venv/bin/httpx
app/.venv/bin/jsonschema
app/.venv/bin/mcp
app/.venv/bin/nautilus
app/.venv/bin/normalizer
app/.venv/bin/opentelemetry-bootstrap
app/.venv/bin/opentelemetry-instrument
app/.venv/bin/python
app/.venv/bin/python3
app/.venv/bin/python3.14
app/.venv/bin/uvicorn
app/.venv/bin/watchfiles
app/.venv/bin/websockets
usr/local/bin/python3
usr/local/bin/python3.14
$ docker rm "$cid" > /dev/null
```

The four traditional `bin` directories contribute nothing: `/usr/bin` and
`/usr/sbin` are empty, and `/bin` and `/sbin` are symlinks to them. Only
`/usr/local/bin` (the interpreter) and the venv have anything in them. Run that
grep on your own build before you believe any recipe on this page — an image
built some other way is yours to check, not ours.

So: CPython 3.14 with its whole standard library, reachable as `python`,
`python3` or `/app/.venv/bin/python`, plus the `nautilus` console script,
because the venv's `bin` is first on `PATH`:

```console
$ docker image inspect -f '{{index .Config.Env 0}}' nautilus:0.2.6.dev0
PATH=/app/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

That covers reading, listing, permissions, renaming, deleting and HTTP. It does
not cover changing ownership or installing anything, and those two are
genuinely impossible from inside — [§11.4](#114-what-you-cannot-do-from-inside)
says what to do instead.

### 11.1 Reading

`nautilus` subcommands need no shell at all — they are the entrypoint's own
console script:

```console
$ docker exec nautilus nautilus version
0.2.6.dev0
build: unknown
$ docker exec nautilus nautilus health
OK 200 http://localhost:8000/readyz
```

(`build: unknown` means the image was built without
`--build-arg BUILD_REV=$(git rev-parse HEAD)`; see [§1](#1-the-image).)

Read a file — this is the replacement for `cat`:

```console
$ docker exec nautilus python -c "print(open('/config/nautilus.yaml').read())" | head -4
sources:
  - id: orders
    type: static
    description: order rows
```

List a directory with modes, owners, sizes and mtimes — the replacement for
`ls -l`. `stat.filemode` renders the same `-rw-------` string `ls` does:

```console
$ docker exec nautilus python -c "
import os, stat, time
d = '/var/lib/nautilus'
for n in sorted(os.listdir(d)):
    s = os.stat(os.path.join(d, n))
    print(f'{stat.filemode(s.st_mode)} {s.st_uid}:{s.st_gid} {s.st_size:>8} {time.strftime(\"%Y-%m-%dT%H:%M:%SZ\", time.gmtime(s.st_mtime))} {n}')
"
-rw------- 65532:65532      403 2026-09-02T03:27:20Z keyring.json
-rw-r--r-- 65532:65532        0 2026-09-02T03:27:20Z keyring.json.lock
-rw-r--r-- 65532:65532     4096 2026-09-02T03:27:21Z sessions.db
-rw-r--r-- 65532:65532    32768 2026-09-02T03:27:21Z sessions.db-shm
-rw-r--r-- 65532:65532    16512 2026-09-02T03:27:21Z sessions.db-wal
```

Ask which of the mounts you can actually write. This one answer explains most
readiness failures, and it is the first thing to run when [§6](#6-probes) tells
you a path is not writable:

```console
$ docker exec nautilus python -c "
import os
for d in ('/', '/tmp', '/app', '/config', '/etc/nautilus/keys', '/var/lib/nautilus', '/var/log/nautilus'):
    print(f'{\"rw\" if os.access(d, os.W_OK) else \"ro\"}  {d}')"
ro  /
rw  /tmp
ro  /app
ro  /config
ro  /etc/nautilus/keys
rw  /var/lib/nautilus
rw  /var/log/nautilus
```

`/` is read-only because of `readOnlyRootFilesystem: true` / `--read-only`;
`/config` and `/etc/nautilus/keys` because they are mounted `ro`. The two `rw`
lines are the `state` and `audit` volumes from [§5](#5-volumes-and-mounts).

### 11.2 Probing the broker's own HTTP surface

`curl` is not in the image. `urllib.request` is, and it reaches the loopback
listener that `-p` / the Service may not expose:

```console
$ docker exec nautilus python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/v1/keys/jwks.json').read().decode())"
{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"834e7ee1-b86d-4d6d-b34a-1c3e4372a640","x":"rfPubI4g9sRShE-tbtJLCvj7ZhKPR2tj6El786S5WfA","use":"sig"}]}
```

For an authenticated route add the header the same way —
`urllib.request.Request(url, headers={'X-API-Key': ...}, data=..., method='POST')`.
Note that this puts the key in the process table of the pod; prefer
`kubectl port-forward` and a client on your laptop when you have the choice.

The other way in needs nothing from the image at all: an ephemeral container
joined to the running container's **network** namespace. It brings its own
`wget`, and it does not require the target to cooperate:

```console
$ docker run --rm --network=container:nautilus busybox:latest wget -qO- http://127.0.0.1:8000/healthz
{"status":"ok","version":"0.2.6.dev0","build":"unknown"}
```

On Kubernetes that is `kubectl debug -it <pod> --image=busybox --target=<container>`;
an ephemeral container in a pod already shares the pod's network namespace.

### 11.3 Writing, renaming and fixing permissions

`os.chmod`, `os.rename`, `os.remove` and `os.makedirs` are the replacements for
`chmod`, `mv`, `rm` and `mkdir -p`, and they work on anything the broker's own
UID owns. Reproducing the [§6](#6-probes) `not writable` readiness failure and
then repairing it, with no shell and no restart:

```console
$ docker exec nautilus python -c "import os; os.chmod('/var/log/nautilus/audit.jsonl', 0o444)"
$ curl -s -w ' HTTP %{http_code}\n' localhost:8000/readyz
{"status":"not_ready","reason":"audit log /var/log/nautilus/audit.jsonl is not writable"} HTTP 503
$ curl -s -w ' HTTP %{http_code}\n' localhost:8000/healthz
{"status":"ok","version":"0.2.6.dev0","build":"unknown"} HTTP 200
$ docker exec nautilus python -c "import os; os.chmod('/var/log/nautilus/audit.jsonl', 0o644)"
$ curl -s -w ' HTTP %{http_code}\n' localhost:8000/readyz
{"status":"ok"} HTTP 200
```

Readiness recovers on the next probe — `periodSeconds: 10` — with no rollout.
`/healthz` stays `200` throughout, which is the whole reason liveness and
readiness are different endpoints.

**When the file is owned by someone else**, `chmod` is not available to you at
any privilege you hold, but `rename` is: the permission that governs renaming a
file is write on its *directory*, not on the file. So move the bad file aside
and let the broker create a fresh one on the next probe. This is the fix for
the `audit log … is not writable` 503 caused by a volume first written by a
root-run container:

```console
$ docker exec nautilus python -c "import os,stat; p='/var/log/nautilus/audit.jsonl'; s=os.stat(p); print(oct(stat.S_IMODE(s.st_mode)), s.st_uid, s.st_gid, os.access(p, os.W_OK), os.access('/var/log/nautilus', os.W_OK))"
0o644 0 0 False True
$ docker exec nautilus python -c "import os; os.rename('/var/log/nautilus/audit.jsonl', '/var/log/nautilus/audit.jsonl.root-owned')"
$ curl -s -w ' HTTP %{http_code}\n' localhost:8000/readyz
{"status":"ok"} HTTP 200
```

`0 0` is the owner — root, not 65532 — and `False True` is the whole diagnosis:
the file is not writable, the directory is. The renamed file is still there and
still holds every record written before the problem; copy it out with the
recipe below and then delete it. If the audit log is chained
(`audit.chained: true`) the new file starts a **new chain**: verify the old one
separately, because `nautilus attestation verify` follows one file.

**Copying a file out.** `docker cp` needs nothing in the container — it goes
through the daemon:

```console
$ docker cp nautilus:/var/lib/nautilus/keyring.json ./keyring.json
$ echo $?
0
```

It prints nothing on success, which is why the `echo $?` is there.

`kubectl cp` is **not** the equivalent and will fail here. Its own help says so:

```console
$ kubectl cp --help | grep -A3 'Important Note'
  # !!!Important Note!!!
  # Requires that the 'tar' binary is present in your container
  # image.  If 'tar' is not present, 'kubectl cp' will fail.
  #
```

Stream the bytes through `exec` instead. This is byte-exact, including for a
SQLite database:

```console
$ docker exec nautilus \
    python -c "import sys; sys.stdout.buffer.write(open('/var/lib/nautilus/sessions.db','rb').read())" > sessions.db
$ docker exec nautilus \
    python -c "import hashlib; print(hashlib.sha256(open('/var/lib/nautilus/sessions.db','rb').read()).hexdigest())"
44e9b382070d7cf97c2d422aaa250eee7edbe9a9fa39516c42c54ccea43cae81
$ sha256sum sessions.db
44e9b382070d7cf97c2d422aaa250eee7edbe9a9fa39516c42c54ccea43cae81  sessions.db
```

`kubectl -n nautilus exec deploy/nautilus --` in place of `docker exec nautilus`
does the same thing — this is the replacement for `kubectl cp` out of a
distroless pod.

Do not use `-t`/`--tty`: a TTY translates `\n` to `\r\n` and corrupts binary.
Compare the two hashes every time — that is the check, not a formality. Copying
`sessions.db` off a *running* broker gives you a torn database whatever the
hashes say; see
[Back up](../docs/how-to/operator-guide.md#back-up) for why the `-wal` matters.

### 11.4 What you cannot do from inside

These four have no in-container answer. The workaround column is the answer.

| Impossible inside the container | Why | Do this instead |
|---|---|---|
| `chown` | the process is UID 65532 with `capabilities.drop: ["ALL"]`, so it has no `CAP_CHOWN` | for a bind mount, `sudo chown -R 65532:65532 <hostdir>` on the **host** ([§2.1](#21-lay-out-the-host-directories)); on Kubernetes, `fsGroup: 65532`, which the shipped `deployment.yaml` already sets. Or rename the file aside as in [§11.3](#113-writing-renaming-and-fixing-permissions) |
| edit `nautilus.yaml` in place | `/config` is a `ro` mount of a ConfigMap | edit the ConfigMap (or the host file), then `kubectl rollout restart` — or send `SIGHUP`, which reloads the subset that can be reloaded safely and names what it refused |
| install a package | no `pip`, no package manager, no writable `/usr` | add it to `pyproject.toml` and rebuild; or bring your own tools in an ephemeral container, [below](#getting-a-real-shell-next-to-the-container) |
| write anywhere but the two volumes and `/tmp` | `readOnlyRootFilesystem: true` | use `/var/lib/nautilus` (persisted with the `state` volume) or `/tmp` (a 16 MiB tmpfs, gone on restart) |

The `chown` failure and the read-only root, verbatim, so you can recognise them
in a log rather than guessing:

```console
$ docker exec nautilus python -c "import os; os.chown('/var/log/nautilus/audit.jsonl', 0, 0)" 2>&1 | tail -1
PermissionError: [Errno 1] Operation not permitted: '/var/log/nautilus/audit.jsonl'
$ docker exec nautilus python -c "open('/probe','w').write('x')" 2>&1 | tail -1
OSError: [Errno 30] Read-only file system: '/probe'
$ docker exec nautilus python -c "open('/config/nautilus.yaml','a').write('x')" 2>&1 | tail -1
PermissionError: [Errno 13] Permission denied: '/config/nautilus.yaml'
```

`SIGHUP` is worth knowing before you reach for a rollout — it re-reads the
config file and applies what it can prove safe:

```console
$ docker kill -s HUP nautilus
nautilus
$ until docker logs nautilus 2>&1 | grep 'SIGHUP: '; do sleep 0.2; done
INFO:nautilus.cli.serve:SIGHUP: reloaded /config/nautilus.yaml (no reloadable key changed)
```

Two lines in a running log say `SIGHUP`. The startup notice — `SIGHUP reloads
sources, rules and the live session_store limits from …` — only means the
handler is wired, and it is there before you signal anything. The *result* of a
reload always carries the colon: `SIGHUP: reloaded …`, or `SIGHUP: refused; …`
when the new file is rejected and the running config keeps answering. That
colon is what the filter matches. Do not use `--tail 1` here — a readiness
probe lands between the signal and the read often enough to show you an access
log instead — and the `until` loop is what waits for the reload to finish
rather than for the log to be read.

### Getting a real shell next to the container

Not *in* it — beside it. An ephemeral container in the target's namespaces
brings its own `sh`, `ls`, `mv` and `chown`, and needs nothing from the
distroless image. Reaching the target's filesystem through `/proc/1/root` also
needs `CAP_SYS_PTRACE`, which is **not** in Docker's default set: without
`--cap-add SYS_PTRACE` the path exists and every access to it is denied.

```console
$ docker run --rm --pid=container:nautilus busybox:latest ls -l /proc/1/root/var/log/nautilus
ls: /proc/1/root/var/log/nautilus: Permission denied
$ docker run --rm --cap-add SYS_PTRACE --pid=container:nautilus busybox:latest ls -l /proc/1/root/var/log/nautilus
total 8
-rw-r--r--    1 65532    65532         3070 Sep  2 03:34 audit.jsonl
-rw-r--r--    1 root     root             3 Sep  2 03:30 audit.jsonl.root-owned
```

Mounting the volume into an ordinary container is simpler when you have the
host, and needs no capability at all:
`docker run --rm -u 0:0 -v /srv/nautilus/audit:/a busybox chown -R 65532:65532 /a`.

On Kubernetes the equivalent is
`kubectl debug -it <pod> --image=busybox --target=<container>`, and the same
capability caveat applies — `--profile=sysadmin` is the flag that grants it
(`kubectl debug --help` lists `legacy`, `general`, `baseline`, `netadmin`,
`restricted`, `sysadmin`). Two things to expect: a namespace enforcing the
`restricted` Pod Security Standard will reject that profile, which is the same
admission rule that makes this Deployment safe; and `kubectl debug --help`
warns that "when a non-root user is configured for the entire target Pod, some
capabilities granted by debug profile may not work", which is exactly this pod.

**Do not reach for `--target debug`.** The Dockerfile's `debug` stage has
`bash`, but swapping an image means a rebuild and a new rollout — the pod whose
state you wanted to look at is gone by the time the shell exists. It is for
reproducing a problem locally, never for diagnosing a live one.

---

## 12. Why the manifests look like this

- **The ConfigMap holds no credentials.** Source DSNs and the API key are
  `${ENV}` references resolved from the Secret at config load, so the file you
  paste into a ticket has nothing in it.
- **`readOnlyRootFilesystem: true`** with two explicit writable mounts. The
  broker writes to `/var/lib/nautilus` and `/var/log/nautilus` and nowhere
  else; anything that tries elsewhere fails loudly instead of leaving state
  somewhere nobody backs up.
- **`runAsNonRoot: true` / `runAsUser: 65532`** matches the image's own
  `USER 65532:65532`, so a cluster that enforces non-root does not have to
  guess. `fsGroup: 65532` is what makes the two writable volumes writable.
- **`capabilities.drop: ["ALL"]`, `allowPrivilegeEscalation: false`,
  `seccompProfile: RuntimeDefault`** — together with the above, this pod
  satisfies the `restricted` Pod Security Standard as shipped.
- **`automountServiceAccountToken: false`** — the broker never calls the
  Kubernetes API, so there is no reason for a cluster credential to sit in its
  filesystem.
- **`/readyz` is the readiness probe, not `/healthz`.** It fails when the
  session store or the audit sink is unwritable, which is exactly when a
  replica must stop taking requests. `/healthz` answers as long as the process
  is alive, which is the right question for liveness and the wrong one for
  routing.
- **No CPU limit, a 1-core request.** Per-request work is dominated by
  synchronous CPU on a single event loop, so throughput does not rise with
  concurrency: the pod cannot use more than a core, and a limit would only add
  throttling.
- **`strategy: Recreate`.** At `replicas: 1` the default `RollingUpdate`
  rounds `maxSurge: 25%` up to 1 and briefly runs two brokers — see
  [§8](#8-replicas-what-actually-breaks-at-two).
