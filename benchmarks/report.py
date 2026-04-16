"""JSON report builder for Locust benchmark results.

Extracts p50/p95/p99 latencies, throughput, and error rate from
Locust's stats dictionary.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def generate_report(stats: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON-serializable report from Locust stats.

    Args:
        stats: Locust stats dictionary. Expected keys:
            - ``requests``: mapping of ``(method, name)`` string keys
              to stat entries with ``response_times`` percentiles.
            - ``total``: aggregated stat entry.
            - ``errors``: mapping of error keys to error dicts.

    Returns:
        Report dict with latencies, throughput, error_rate, and
        per-endpoint breakdown.
    """
    total = stats.get("total", {})
    errors = stats.get("errors", {})
    requests = stats.get("requests", {})

    total_reqs = total.get("num_requests", 0)
    total_fails = total.get("num_failures", 0)
    error_rate = (total_fails / total_reqs * 100) if total_reqs > 0 else 0.0

    response_times = total.get("response_times", {})

    report: dict[str, Any] = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "summary": {
            "total_requests": total_reqs,
            "total_failures": total_fails,
            "error_rate_pct": round(error_rate, 2),
            "throughput_rps": round(total.get("current_rps", 0.0), 2),
            "latency_ms": {
                "p50": response_times.get(0.50, 0),
                "p95": response_times.get(0.95, 0),
                "p99": response_times.get(0.99, 0),
                "min": total.get("min_response_time", 0),
                "max": total.get("max_response_time", 0),
                "avg": round(total.get("avg_response_time", 0.0), 2),
            },
        },
        "endpoints": _extract_endpoints(requests),
        "errors": [
            {
                "method": err.get("method", ""),
                "name": err.get("name", ""),
                "message": err.get("error", ""),
                "occurrences": err.get("occurrences", 0),
            }
            for err in errors.values()
        ],
    }
    return report


def _extract_endpoints(
    requests: dict[str, Any],
) -> list[dict[str, Any]]:
    """Extract per-endpoint stats from Locust requests dict."""
    endpoints = []
    for key, entry in requests.items():
        rt = entry.get("response_times", {})
        endpoints.append(
            {
                "name": key,
                "num_requests": entry.get("num_requests", 0),
                "num_failures": entry.get("num_failures", 0),
                "latency_ms": {
                    "p50": rt.get(0.50, 0),
                    "p95": rt.get(0.95, 0),
                    "p99": rt.get(0.99, 0),
                    "avg": round(
                        entry.get("avg_response_time", 0.0), 2
                    ),
                },
                "throughput_rps": round(
                    entry.get("current_rps", 0.0), 2
                ),
            }
        )
    return endpoints


def write_report(
    stats: dict[str, Any],
    output_dir: str | Path,
    filename: str = "benchmark_report.json",
) -> Path:
    """Generate report and write it to a JSON file.

    Args:
        stats: Locust stats dictionary.
        output_dir: Directory to write the report to.
        filename: Output filename.

    Returns:
        Path to the written report file.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    report = generate_report(stats)
    report_path = out / filename
    report_path.write_text(json.dumps(report, indent=2))
    return report_path
