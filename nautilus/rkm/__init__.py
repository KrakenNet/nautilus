"""Reflexive Knowledge Module (RKM) substrate — #35.1 through #35.10.

Sub-packages:
- :mod:`nautilus.rkm.queue`         — JSONL + ``fcntl.lockf()`` proposal queue.
- :mod:`nautilus.rkm.lineage`       — file-per-rule-version lineage DAG.
- :mod:`nautilus.rkm.audit_emitter` — buffered meta-rule event channel.
- :mod:`nautilus.rkm.curator`       — meta-rule module + isolation check.
- :mod:`nautilus.rkm.validator`     — static → shadow → sandbox → score pipeline.
- :mod:`nautilus.rkm.review`        — CLI backing for queue ops.
- :mod:`nautilus.rkm.types`         — shared dataclasses.

Module-layout source of truth: ``.forge/shared.md`` "Module layout".
"""

from __future__ import annotations
