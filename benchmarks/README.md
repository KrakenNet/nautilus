# Nautilus Benchmarks

Load testing suite for the Nautilus data broker, powered by [Locust](https://locust.io/).

## Prerequisites

- Python 3.14+ (local) or Docker (containerized)
- A running Nautilus broker instance at the target host

## Running locally

```bash
# Install dependencies
pip install -r requirements-bench.txt

# Run with default settings (web UI on http://localhost:8089)
locust -f locustfile.py --host http://localhost:8000

# Run headless (no web UI)
locust -f locustfile.py --host http://localhost:8000 \
    --headless -u 50 -r 10 --run-time 60s
```

## Running via Docker

```bash
# Build the benchmark image
docker build -f Dockerfile.bench -t nautilus-bench .

# Run with Locust web UI (browse to http://localhost:8089)
docker run --rm -p 8089:8089 nautilus-bench \
    -f locustfile.py --host http://host.docker.internal:8000

# Run headless
docker run --rm nautilus-bench \
    -f locustfile.py --host http://host.docker.internal:8000 \
    --headless -u 50 -r 10 --run-time 60s
```

## Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `--host` | Target Nautilus broker URL | (required) |
| `-u` | Number of concurrent users | 1 |
| `-r` | Spawn rate (users per second) | 1 |
| `--run-time` | Test duration (e.g. `60s`, `5m`) | unlimited |
| `--headless` | Disable web UI | off |

## OTel integration

Locust supports OpenTelemetry export via the `--otel` flag for observable load testing:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
    locust -f locustfile.py --host http://localhost:8000 --otel
```

See `observability/docker-compose.otel.yml` for the full collector stack.
