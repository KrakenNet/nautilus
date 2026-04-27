"""NFR-PERF-SIGN benchmark — session-signing latency.

Targets per design:
  * In-process Ed25519 < 10ms p95 @ 1000 iter
  * Vault transit      < 50ms p95 @ 100 iter (skipped here unless VAULT_ADDR set)

Usage:
    uv run python benchmarks/bench_session_signing.py
"""

from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import sys
import time

import rfc8785

from nautilus.core.signer import InProcessEd25519Signer, _build_dsse_envelope

KAT_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"


def _payload() -> dict:
    return {
        "model_id": "gpt-4o-mini",
        "output_hash": "a" * 64,
        "params_hash": "b" * 64,
        "prompt_hash": "c" * 64,
        "timestamp": "2026-04-27T10:00:00.000Z",
    }


async def _bench_inprocess(iterations: int) -> list[float]:
    signer = InProcessEd25519Signer(seed_hex=KAT_SEED, keyid="bench")
    payload = _payload()
    canonical = rfc8785.dumps(payload)
    samples: list[float] = []
    # warm-up
    for _ in range(20):
        await signer.sign(canonical)
    for _ in range(iterations):
        start = time.perf_counter()
        await _build_dsse_envelope(payload, signer)
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


def _percentile(samples: list[float], pct: float) -> float:
    s = sorted(samples)
    k = max(0, int(round(pct / 100.0 * (len(s) - 1))))
    return s[k]


async def _main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000)
    args = parser.parse_args()

    samples = await _bench_inprocess(args.iterations)
    p50 = _percentile(samples, 50)
    p95 = _percentile(samples, 95)
    p99 = _percentile(samples, 99)
    mean = statistics.mean(samples)
    print(
        f"InProcessEd25519 dsse-envelope: n={len(samples)} mean={mean:.3f}ms"
        f" p50={p50:.3f}ms p95={p95:.3f}ms p99={p99:.3f}ms"
    )
    target = 10.0  # ms
    status = "PASS" if p95 < target else "FAIL"
    print(f"  target: p95 < {target}ms — {status}")
    if os.environ.get("VAULT_ADDR"):
        print("VAULT_ADDR set; transit benchmark would run here in a live environment")
    return 0 if p95 < target else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
