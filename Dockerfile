# syntax=docker/dockerfile:1.7
#
# Nautilus reasoning-engine image — multi-stage (FR-31, FR-32, D-16, D-17,
# NFR-10, design §3.16).
#
# Stages:
#   builder  — uv-based Debian slim image that resolves dependencies into
#              /app/.venv using uv.lock (deterministic, no dev deps).
#   runtime  — distroless/cc image that only carries the venv + nautilus
#              package. No shell, no package manager (AC-16.5).
#   debug    — optional python:3.14-slim target with bash for operator
#              inspection; NOT built by CI (UQ-5 / D-17).
#
# Default target is `runtime`. Build with:
#     docker build -t nautilus:latest .
# Debug target is opt-in:
#     docker build --target debug -t nautilus:debug .

############################
# Stage 1 — builder        #
############################
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim AS builder

# Avoid writing .pyc files and buffering stdout during build.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=0 \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Copy the lockfile + project manifest first so the dependency resolution
# layer caches when only source changes (AC-16.6).
COPY pyproject.toml uv.lock README.md /app/

# Resolve runtime dependencies into /app/.venv. `--no-dev` drops the
# pytest/ruff/pyright/testcontainers stack. Two-step install: (1) sync
# deps without the project (keeps this layer cacheable across source
# edits), then (2) re-sync with the project after source is copied so
# importlib.metadata can resolve `nautilus` at runtime (powers `nautilus
# version` / FR-30).
# ``--extra otel`` is not optional for the published image: without it every
# metric is a no-op stub and ``GET /metrics`` raises ImportError, i.e. a 500
# on every Prometheus scrape the monitoring guide tells operators to set up.
RUN uv sync --frozen --no-dev --extra otel --no-install-project

# Copy the application source last so edits don't bust the dep layer.
COPY nautilus /app/nautilus

# Install the nautilus package itself so `importlib.metadata.version` works.
RUN uv sync --frozen --no-dev --extra otel

############################
# Stage 2 — runtime        #
############################
FROM gcr.io/distroless/cc-debian13 AS runtime

# Copy the prepared /app tree (venv + nautilus source) from the builder.
COPY --from=builder /app /app

# Make the bundled python + nautilus package importable without a shell.
# distroless has no /bin/sh, so we rely on the interpreter directly.
ENV PYTHONPATH=/app \
    PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Drop root (distroless ships a `nonroot` user at UID/GID 65532).
USER 65532:65532

# No shell available — invoke the interpreter directly (exec form).
# ``--bind 0.0.0.0``: ``nautilus serve`` defaults to 127.0.0.1, which inside a
# container means "serve nobody" — and the HEALTHCHECK below probes localhost
# from inside the same namespace, so that misconfiguration reported healthy.
ENTRYPOINT ["/app/.venv/bin/python", "-m", "nautilus"]
CMD ["serve", "--config", "/config/nautilus.yaml", "--bind", "0.0.0.0"]

# HEALTHCHECK runs the CLI's `health` subcommand which probes /readyz via
# urllib (no external binary needed — NFR-10). Exec form is mandatory on
# distroless since `CMD-SHELL` would require /bin/sh.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/.venv/bin/python", "-m", "nautilus", "health"]

############################
# Stage 3 — debug (opt-in) #
############################
# Operator-local only. NOT produced by CI (D-17 / UQ-5). Use for shelling
# into a layer that mirrors `runtime` but with bash + apt available.
FROM python:3.14-slim AS debug

ENV PYTHONPATH=/app \
    PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Bring in bash + a few diagnostics. Kept minimal to avoid bloat even for
# the debug target.
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app /app

ENTRYPOINT ["/app/.venv/bin/python", "-m", "nautilus"]
CMD ["serve", "--config", "/config/nautilus.yaml", "--bind", "0.0.0.0"]
