# syntax=docker/dockerfile:1.7
#
# Nautilus reasoning-engine image — multi-stage (FR-31, FR-32, D-16, D-17,
# NFR-10, design §3.16).
#
# Stages:
#   builder  — uv-based Debian slim image that resolves dependencies into
#              /app/.venv using uv.lock (deterministic, no dev deps).
#   debug    — optional python:3.14-slim target with bash for operator
#              inspection; NOT built by CI (UQ-5 / D-17).
#   runtime  — distroless/cc image carrying the interpreter, the venv and the
#              nautilus package. No shell, no package manager (AC-16.5).
#              Declared last, so it is what a bare `docker build .` selects.
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
#
# Adapter drivers are NOT in the default image (deploy/deployment.yaml says so)
# and cannot be added to one: the runtime stage is distroless, with no shell
# and no pip. So the only place to add them is here, at build time:
#     docker build --build-arg EXTRAS="--extra postgres" -t nautilus:1.0.0-postgres .
# Empty by default, which keeps the published image driver-free.
ARG EXTRAS=""

RUN uv sync --frozen --no-dev --extra otel ${EXTRAS} --no-install-project

# Copy the application source last so edits don't bust the dep layer.
COPY nautilus /app/nautilus

# Install the nautilus package itself so `importlib.metadata.version` works.
# ``${EXTRAS}`` is repeated because ``uv sync`` makes the environment match the
# request exactly: syncing without it here would uninstall what the layer
# above installed.
RUN uv sync --frozen --no-dev --extra otel ${EXTRAS}

############################
# Stage 2 — debug (opt-in) #
############################
# Operator-local only. NOT produced by CI (D-17 / UQ-5). Use for shelling
# into a layer that mirrors `runtime` but with bash + apt available.
# Declared BEFORE runtime: the last stage in the file is what a bare
# ``docker build .`` selects, and this one carries a shell and a package
# manager. Ordered the other way it silently won the documented default.
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
CMD ["serve", "--config", "/config/nautilus.yaml", "--bind", "0.0.0.0:8000"]

############################
# Stage 3 — runtime        #
############################
FROM gcr.io/distroless/cc-debian13 AS runtime

# The interpreter, first. ``/app/.venv/bin/python`` is a symlink into
# /usr/local on the builder, so copying only /app produced an image that
# built, inspected and measured perfectly and could not execute a byte:
#   exec: "/app/.venv/bin/python": no such file or directory
# distroless/cc supplies glibc and libstdc++; CPython needs its own binary,
# its shared library and its standard library on top of that.
COPY --from=builder /usr/local/bin/python3.14 /usr/local/bin/python3.14
COPY --from=builder /usr/local/bin/python3 /usr/local/bin/python3
COPY --from=builder /usr/local/lib/libpython3.14.so.1.0 /usr/local/lib/
COPY --from=builder /usr/local/lib/python3.14 /usr/local/lib/python3.14

# The C libraries the stdlib's extension modules link against. distroless/cc
# carries libc, libm, libgcc_s and libstdc++ and nothing else, so without these
# ``import sqlite3`` (the session store's fallback backend), ``import ssl`` and
# ``import hashlib`` all fail at runtime on an image that started fine.
# Enumerated from `ldd` over lib-dynload on the builder; tcl/tk are omitted
# because tkinter has no place in a server image.
COPY --from=builder \
    /lib/x86_64-linux-gnu/libbz2.so.1.0 \
    /lib/x86_64-linux-gnu/libcrypto.so.3 \
    /lib/x86_64-linux-gnu/libdb-5.3.so \
    /lib/x86_64-linux-gnu/libffi.so.8 \
    /lib/x86_64-linux-gnu/libgdbm.so.6 \
    /lib/x86_64-linux-gnu/liblzma.so.5 \
    /lib/x86_64-linux-gnu/libncursesw.so.6 \
    /lib/x86_64-linux-gnu/libpanelw.so.6 \
    /lib/x86_64-linux-gnu/libreadline.so.8 \
    /lib/x86_64-linux-gnu/libsqlite3.so.0 \
    /lib/x86_64-linux-gnu/libssl.so.3 \
    /lib/x86_64-linux-gnu/libtinfo.so.6 \
    /lib/x86_64-linux-gnu/libuuid.so.1 \
    /lib/x86_64-linux-gnu/libz.so.1 \
    /lib/x86_64-linux-gnu/libzstd.so.1 \
    /lib/x86_64-linux-gnu/

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
# ``--bind 0.0.0.0:8000``: ``nautilus serve`` defaults to 127.0.0.1, which inside a
# container means "serve nobody" — and the HEALTHCHECK below probes localhost
# from inside the same namespace, so that misconfiguration reported healthy.
ENTRYPOINT ["/app/.venv/bin/python", "-m", "nautilus"]
CMD ["serve", "--config", "/config/nautilus.yaml", "--bind", "0.0.0.0:8000"]

# HEALTHCHECK runs the CLI's `health` subcommand which probes /readyz via
# urllib (no external binary needed — NFR-10). Exec form is mandatory on
# distroless since `CMD-SHELL` would require /bin/sh.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/.venv/bin/python", "-m", "nautilus", "health"]
