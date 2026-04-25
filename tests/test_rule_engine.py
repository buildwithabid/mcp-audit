from __future__ import annotations

from mcp_audit.models import Severity
from mcp_audit.report import exit_code
from mcp_audit.rules import all_rule_classes, all_rules


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.HIGH < Severity.CRITICAL
    assert Severity.CRITICAL >= Severity.HIGH


def test_all_rules_registered():
    rule_ids = {c.id for c in all_rule_classes()}
    expected = {"MCPA001", "MCPA002", "MCPA003", "MCPA004", "MCPA005", "MCPA006"}
    assert expected.issubset(rule_ids)


def test_rules_are_instantiable():
    rules = all_rules()
    assert len(rules) >= 6
    for r in rules:
        assert r.id and r.title and r.description
        assert isinstance(r.severity, Severity)


def test_rules_sorted_by_id():
    ids = [c.id for c in all_rule_classes()]
    assert ids == sorted(ids)


def test_exit_code_no_findings():
    assert exit_code([], Severity.HIGH) == 0


def test_exit_code_below_threshold(make_server_fixture, tool_factory):
    from mcp_audit.models import Evidence, Finding
    f = Finding(
        rule_id="X", severity=Severity.LOW, title="t", description="d",
        evidence=Evidence(kind="tool", name="x", field=None, snippet=None, extra={}),
        remediation="r",
    )
    assert exit_code([f], Severity.HIGH) == 0


def test_exit_code_at_threshold():
    from mcp_audit.models import Evidence, Finding
    f = Finding(
        rule_id="X", severity=Severity.HIGH, title="t", description="d",
        evidence=Evidence(kind="tool", name="x", field=None, snippet=None, extra={}),
        remediation="r",
    )
    assert exit_code([f], Severity.HIGH) == 1


def test_exit_code_above_threshold():
    from mcp_audit.models import Evidence, Finding
    f = Finding(
        rule_id="X", severity=Severity.CRITICAL, title="t", description="d",
        evidence=Evidence(kind="tool", name="x", field=None, snippet=None, extra={}),
        remediation="r",
    )
    assert exit_code([f], Severity.HIGH) == 1
