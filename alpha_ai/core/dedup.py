"""Finding deduplication across tool runs.

The disk cache dedupes *identical tool invocations*; this dedupes *findings*, so
the same issue surfaced by two different runs (or two tools) collapses to one.

Key = sha256(tool + target + title + evidence). The volatile ``discovered_at``
timestamp is deliberately excluded so re-runs collapse.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from alpha_ai.core.models import Finding


def finding_key(f: Finding) -> str:
    """Stable identity hash for a finding (ignores discovery timestamp)."""
    payload = json.dumps(
        {"tool": f.tool, "target": f.target, "title": f.title, "evidence": f.evidence},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Return findings with duplicates removed, preserving first-seen order."""
    seen: dict[str, Finding] = {}
    for f in findings:
        key = finding_key(f)
        if key not in seen:
            seen[key] = f
    return list(seen.values())
