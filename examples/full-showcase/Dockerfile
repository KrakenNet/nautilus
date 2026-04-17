# Nautilus full-showcase image — includes OTel + LLM extras.
#
# Build from repo root:
#   docker compose -f examples/full-showcase/docker-compose.yml build
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=0 \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

COPY pyproject.toml uv.lock README.md /app/
RUN uv sync --frozen --no-dev --no-install-project --extra otel --extra llm-anthropic --extra llm-openai

COPY nautilus /app/nautilus
COPY rule-packs /app/rule-packs
RUN uv sync --frozen --no-dev --extra otel --extra llm-anthropic --extra llm-openai

FROM python:3.14-slim AS runtime

COPY --from=builder /app /app
WORKDIR /app

ENV PYTHONPATH=/app \
    PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000
ENTRYPOINT ["python", "-m", "nautilus"]
CMD ["serve", "--config", "/config/nautilus.yaml", "--bind", "0.0.0.0:8000"]
