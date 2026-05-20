"""RKM validator pipeline (#35.5 – #35.8).

Stages (run by :func:`nautilus.rkm.validator.pipeline.run_pipeline`):

1. **static**  (#35.5)  — :mod:`.static`  wraps ``Fathom.validate``.
2. **shadow**  (#35.6)  — :mod:`.shadow`  subsumption + fixture loader.
3. **sandbox** (#35.7)  — :mod:`.sandbox` replay harness.
4. **scoring** (#35.8)  — :mod:`.scoring` pure-fn confidence.
"""

from __future__ import annotations
