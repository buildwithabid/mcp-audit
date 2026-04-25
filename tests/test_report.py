from __future__ import annotations

import json

from mcp_audit.models import Evidence, Finding, Severity, Target
from mcp_audit.report import render_json, render_markdown


def _finding(sev: Severity = Severity.HIGH, rule_id: str = "MCPA001") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=sev,
        title="t",
        description="d",
        evidence=Evidence(kind="tool", name="x", field="description", snippet="snip", extra={}),
        remediation="r",
    )


def test_markdown_empty():
    target = Target(type="stdio", value="python s.py")
    md = render_markdown([], target)
    assert "_No findings._" in md
    assert "## Summary" in md


def test_markdown_with_findings():
    target = Target(type="http", value="https://x.example/mcp")
    md = render_markdown([_finding(Severity.CRITICAL), _finding(Severity.LOW, "MCPA005")], target)
    assert "critical" in md
    assert "MCPA001" in md
    assert "MCPA005" in md


def test_json_shape():
    target = Target(type="stdio", value="python s.py")
    out = render_json([_finding(Severity.HIGH)], target)
    payload = json.loads(out)
    assert payload["tool"] == "mcp-audit"
    assert payload["target"]["type"] == "stdio"
    assert payload["summary"]["high"] == 1
    assert payload["summary"]["info"] == 0
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["rule_id"] == "MCPA001"
