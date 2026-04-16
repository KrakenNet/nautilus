"""Locust load harness for Nautilus broker /v1/request endpoint."""

from __future__ import annotations

import os

from locust import HttpUser, between, events, task


class NautilusBenchUser(HttpUser):
    """Simulates an agent hitting the Nautilus broker request endpoint."""

    wait_time = between(0.1, 0.5)

    def on_start(self) -> None:
        api_key = os.environ.get("NAUTILUS_BENCH_API_KEY", "bench-key")
        self._headers = {"X-API-Key": api_key}

    @task
    def broker_request(self) -> None:
        self.client.post(
            "/v1/request",
            json={
                "agent_id": "bench-agent",
                "intent": "benchmark test query",
                "context": {},
            },
            headers=self._headers,
        )


@events.init_command_line_parser.add_listener
def add_custom_args(parser):  # noqa: ANN001, ANN201
    """Add --api-key CLI argument for Locust invocation."""
    parser.add_argument(
        "--api-key",
        type=str,
        default="bench-key",
        help="API key for X-API-Key header",
    )


@events.test_start.add_listener
def on_test_start(environment, **_kwargs):  # noqa: ANN001, ANN201
    """Override API key from CLI if provided."""
    if hasattr(environment, "parsed_options") and environment.parsed_options:
        key = getattr(environment.parsed_options, "api_key", None)
        if key:
            os.environ["NAUTILUS_BENCH_API_KEY"] = key
