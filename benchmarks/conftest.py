"""Pytest fixtures for benchmark report generation tests."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


@pytest.fixture()
def report_output_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for benchmark report output."""
    out = tmp_path / "benchmark_reports"
    out.mkdir()
    return out


@pytest.fixture()
def sample_locust_stats() -> dict:
    """Provide a sample Locust stats dictionary for report tests."""
    return {
        "requests": {
            "POST /v1/request": {
                "num_requests": 1000,
                "num_failures": 5,
                "avg_response_time": 42.3,
                "min_response_time": 8,
                "max_response_time": 312,
                "current_rps": 150.5,
                "response_times": {
                    0.50: 35,
                    0.95: 120,
                    0.99: 250,
                },
            },
        },
        "total": {
            "num_requests": 1000,
            "num_failures": 5,
            "avg_response_time": 42.3,
            "min_response_time": 8,
            "max_response_time": 312,
            "current_rps": 150.5,
            "response_times": {
                0.50: 35,
                0.95: 120,
                0.99: 250,
            },
        },
        "errors": {
            "POST /v1/request:500": {
                "method": "POST",
                "name": "/v1/request",
                "error": "Internal Server Error",
                "occurrences": 5,
            },
        },
    }
