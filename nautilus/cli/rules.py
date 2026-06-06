"""``nautilus rules`` subcommand surface (#35.5 + #35.7 + #34).

Subcommands:
    rules validate <file> [--sandbox] [--replay-n N]
    rules test --file F [--audit-log L] [--threshold 0.6]
    rules history [--module M]

Long-running ``--sandbox`` mode streams ``replaying N/M ...`` progress
to stderr (suppressed when ``--json`` is present).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast


def add_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    """Add ``rules`` group to the top-level argparse subparsers."""
    p_rules = sub.add_parser("rules", help="Rule management subcommands.")
    rules_sub = p_rules.add_subparsers(dest="rules_subcommand", metavar="subcommand")

    p_validate = rules_sub.add_parser("validate", help="Statically validate a rule YAML file.")
    p_validate.add_argument("file", help="Path to the rule YAML file to validate.")
    p_validate.add_argument(
        "--sandbox",
        action="store_true",
        help="Run sandbox replay after static validation.",
    )
    p_validate.add_argument(
        "--replay-n",
        type=int,
        default=1000,
        dest="replay_n",
        help="Number of audit entries to replay in sandbox mode (default: 1000).",
    )
    p_validate.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON.",
    )

    p_test = rules_sub.add_parser(
        "test",
        help="Run the full validator pipeline (static, shadow, sandbox, score) on a rule file.",
    )
    p_test.add_argument(
        "--file",
        required=True,
        help="Path to the rule YAML file to test.",
    )
    p_test.add_argument(
        "--audit-log",
        dest="audit_log",
        default=None,
        help="Audit-log JSONL to replay in the sandbox stage (optional).",
    )
    p_test.add_argument(
        "--threshold",
        type=float,
        default=0.6,
        help="Minimum confidence score to pass (default: 0.6).",
    )
    p_test.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON.",
    )

    p_history = rules_sub.add_parser("history", help="List rule lineage history by module.")
    p_history.add_argument("--module", required=True, metavar="M", help="Module name to filter by.")
    p_history.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON.",
    )


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``rules`` invocation. Returns process exit code."""
    subcommand = getattr(args, "rules_subcommand", None)
    if subcommand == "validate":
        return _cmd_validate(args)
    if subcommand == "test":
        return _cmd_test(args)
    if subcommand == "history":
        return _cmd_history(args)
    print("ERROR: unknown rules subcommand", file=sys.stderr)
    return 2


def _cmd_validate(args: argparse.Namespace) -> int:
    """Run static validation on the given rule YAML file."""
    from nautilus.rkm.validator.static import validate_static

    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"ERROR: file not found: {file_path}", file=sys.stderr)
        return 1

    result = validate_static(file_path)
    if result.ok:
        print(f"OK: {file_path}")
        return 0

    for err in result.errors:
        hint_suffix = f" Hint: {err.hint}" if err.hint else ""
        print(
            f"ERROR {err.file}:{err.line}: {err.message}{hint_suffix}",
            file=sys.stderr,
        )
    return 1


def _cmd_test(args: argparse.Namespace) -> int:
    """Run the full validator pipeline on a rule YAML file (#34).

    Stages mirror :func:`nautilus.rkm.validator.pipeline.run_pipeline`
    (static → shadow → sandbox → score) without queueing a proposal.
    Shadow comparison is against the other rules in the same file.

    Exit codes: 0 pass, 1 validation failure (static error or sandbox
    regression), 2 score below ``--threshold``.
    """
    import os

    import yaml

    from nautilus.cli._common import err, ok, warn
    from nautilus.rkm.types import ConfidenceBreakdown
    from nautilus.rkm.validator.sandbox import (
        SandboxRegressionError,
        SandboxResult,
        sandbox_replay,
    )
    from nautilus.rkm.validator.scoring import score
    from nautilus.rkm.validator.shadow import ShadowFlag, shadow_check
    from nautilus.rkm.validator.static import validate_static

    file_path = Path(args.file)
    if not file_path.is_file():
        err(f"file not found: {file_path}")
        return 1

    if args.audit_log is not None:
        audit_path = Path(args.audit_log)
        if not audit_path.is_file():
            err(f"audit log not found: {audit_path}")
            return 1
    else:
        # No audit log: the sandbox stage replays zero entries and the
        # result carries insufficient_history=True (surfaced as WARN).
        audit_path = Path(os.devnull)

    # Stage 1 — static analysis (same surface as ``rules validate``).
    static_result = validate_static(file_path)
    if not static_result.ok:
        for serr in static_result.errors:
            hint_suffix = f" Hint: {serr.hint}" if serr.hint else ""
            print(
                f"ERROR {serr.file}:{serr.line}: {serr.message}{hint_suffix}",
                file=sys.stderr,
            )
        return 1

    # Static validation guarantees a top-level 'rules' list of mappings.
    data = cast("dict[str, Any]", yaml.safe_load(file_path.read_text(encoding="utf-8")))
    rules: list[dict[str, Any]] = [
        dict(cast("dict[str, Any]", r)) for r in cast("list[Any]", data["rules"])
    ]
    # The shadow/sandbox heuristics read LHS conditions from 'lhs';
    # shipped rule packs author them under 'when'. Alias so the
    # pipeline sees the conditions either way.
    for rule in rules:
        if "lhs" not in rule and "when" in rule:
            rule["lhs"] = rule["when"]
    if not rules:
        warn(f"no rules found in {file_path}")

    # Stages 2–4 per rule — shadow → sandbox → score.
    results: list[tuple[str, tuple[ShadowFlag, ...], SandboxResult, ConfidenceBreakdown]] = []
    min_total = 1.0
    for rule in rules:
        name = str(rule.get("name", "<unnamed>"))
        flags = shadow_check(rule, [r for r in rules if r is not rule])
        try:
            sandbox_result = sandbox_replay(rule, audit_path)
        except SandboxRegressionError as exc:
            err(f"rule '{name}': {exc}")
            return 1
        breakdown = score(sandbox_result, flags)
        min_total = min(min_total, breakdown.total)
        results.append((name, flags, sandbox_result, breakdown))

    threshold = float(args.threshold)

    if getattr(args, "json", False):
        payload: dict[str, Any] = {
            "file": str(file_path),
            "threshold": threshold,
            "score": min_total,
            "passed": min_total >= threshold,
            "rules": [
                {
                    "name": name,
                    "score": breakdown.total,
                    "breakdown": {
                        "base": breakdown.base,
                        "regression_penalty": breakdown.regression_penalty,
                        "relaxation_penalty": breakdown.relaxation_penalty,
                        "shadow_penalty": breakdown.shadow_penalty,
                        "fire_rate_penalty": breakdown.fire_rate_penalty,
                        "cascade_penalty": breakdown.cascade_penalty,
                    },
                    "shadow_flags": [
                        {"existing_rule": f.existing_rule, "relation": f.relation} for f in flags
                    ],
                    "sandbox": {
                        "replayed_n_actual": sandbox_result.replayed_n_actual,
                        "fired": sandbox_result.fired,
                        "regressions": sandbox_result.regressions,
                        "relaxations": sandbox_result.relaxations,
                        "cascade_max": sandbox_result.cascade_max,
                        "insufficient_history": sandbox_result.insufficient_history,
                    },
                }
                for name, flags, sandbox_result, breakdown in results
            ],
        }
        print(json.dumps(payload))
        return 0 if min_total >= threshold else 2

    for name, flags, sandbox_result, breakdown in results:
        for flag in flags:
            warn(
                f"rule '{name}': shadow finding {flag.relation}"
                f" (existing rule '{flag.existing_rule}')"
            )
        if sandbox_result.insufficient_history:
            warn(
                f"rule '{name}': insufficient audit history"
                f" (replayed {sandbox_result.replayed_n_actual} entries)"
            )
        print(
            f"rule '{name}': score={breakdown.total:.2f}"
            f" fired={sandbox_result.fired}/{sandbox_result.replayed_n_actual}"
            f" relaxations={sandbox_result.relaxations}"
            f" shadow_flags={len(flags)}"
        )

    if min_total < threshold:
        err(f"score {min_total:.2f} below threshold {threshold:.2f}: {file_path}")
        return 2
    ok(f"{file_path} score={min_total:.2f} (threshold {threshold:.2f})")
    return 0


def _cmd_history(args: argparse.Namespace) -> int:
    """List rule lineage history filtered by module."""
    from nautilus.rkm.lineage import LineageStore

    store = LineageStore()
    # Filter: list_by_derived_from uses parent_id; for module filter we
    # scan all records and match rule_name prefix == module.
    all_records = store._all_records()  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    module = args.module
    matching = [
        r for r in all_records if r.rule_name.startswith(f"{module}/") or r.rule_name == module
    ]

    if getattr(args, "json", False):
        output: list[dict[str, object]] = []
        for rec in sorted(matching, key=lambda r: (r.rule_name, r.version)):
            output.append(
                {
                    "rule_name": rec.rule_name,
                    "version": rec.version,
                    "proposer": rec.proposer,
                    "approver": rec.approver,
                    "promoted_at": rec.promoted_at.isoformat(),
                    "derived_from": list(rec.derived_from),
                    "retired_at": rec.retired_at.isoformat() if rec.retired_at else None,
                }
            )
        print(json.dumps(output))
        return 0

    if not matching:
        print(f"No lineage records found for module '{module}'.")
        return 0

    for rec in sorted(matching, key=lambda r: (r.rule_name, r.version)):
        retired = f"  [retired: {rec.retired_at.isoformat()}]" if rec.retired_at else ""
        chain = " -> ".join(rec.derived_from) if rec.derived_from else "(root)"
        print(f"{rec.rule_name} v{rec.version}  proposer={rec.proposer}  chain={chain}{retired}")
    return 0


__all__ = ["add_subparser", "dispatch"]
