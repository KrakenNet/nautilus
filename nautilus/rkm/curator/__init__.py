"""Curator meta-rule package (#35.3) — isolated from routing module.

The ``curator`` Fathom module hosts the ``pattern-tracker`` meta-rules
(track-sequential-requests, strengthen-relationship-candidate) and is
forbidden from asserting facts in the ``routing`` module's templates
(AC-35.3.e — verified by :func:`assert_module_isolation`).
"""

from __future__ import annotations
