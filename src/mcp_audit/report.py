from __future__ import annotations

import json
from typing import Any

from mcp_audit import __version__
from mcp_audit.models import Finding, Severity, Target, severity_counts

_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
_SEVERITY_BADGE = {
    Severity.CRITICAL: "🟥 critical",
    Severity.HIGH: "🟧 high",
    Severity.MEDIUM: "🟨 medium",
    Severity.LOW: "🟦 low",
    Severity.INFO: "⬜ info",
}


def render_markdown(findings: list[Finding], target: Target) -> str:
    counts = severity_counts(findings)
    lines: list[str] = []
    lines.append(f"# mcp-audit report — `{target.value}`")
    lines.append("")
    lines.append(f"**Target:** `{target.type}` · **Tool:** mcp-audit {__version__}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {_SEVERITY_BADGE[sev]} | {counts[sev]} |")
    lines.append("")
    if not findings:
        lines.append("_No findings._")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    grouped: dict[Severity, list[Finding]] = {sev: [] for sev in _SEVERITY_ORDER}
    for f in findings:
        grouped[f.severity].append(f)

    for sev in _SEVERITY_ORDER:
        items = grouped[sev]
        if not items:
            continue
        lines.append(f"### {_SEVERITY_BADGE[sev]} ({len(items)})")
        lines.append("")
        for f in items:
            lines.append(f"#### `{f.rule_id}` — {f.title}")
            lines.append("")
            lines.append(f.description)
            lines.append("")
            lines.append(f"**Where:** `{f.evidence.kind}` `{f.evidence.name}`"
                         + (f" · field `{f.evidence.field}`" if f.evidence.field else ""))
            lines.append("")
            if f.evidence.snippet:
                lines.append("```")
                lines.append(f.evidence.snippet)
                lines.append("```")
                lines.append("")
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
    return "\n".join(lines)


def render_json(findings: list[Finding], target: Target) -> str:
    counts = severity_counts(findings)
    payload: dict[str, Any] = {
        "tool": "mcp-audit",
        "version": __version__,
        "target": target.model_dump(),
        "summary": {sev.value: n for sev, n in counts.items()},
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    return json.dumps(payload, indent=2)


def exit_code(findings: list[Finding], fail_on: Severity) -> int:
    return 1 if any(f.severity >= fail_on for f in findings) else 0
