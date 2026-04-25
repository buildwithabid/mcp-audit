from __future__ import annotations

from mcp_audit.rules.oauth_scopes import OAuthScopesRule


def test_skipped_for_stdio(make_server_fixture):
    server = make_server_fixture(target_type="stdio", target_value="python s.py")
    assert OAuthScopesRule().check(server) == []


def test_info_when_no_metadata(make_server_fixture):
    server = make_server_fixture(target_type="http", target_value="https://x.example/mcp")
    findings = OAuthScopesRule().check(server)
    assert findings
    assert findings[0].severity.value == "info"


def test_high_when_admin_scope_in_instructions(make_server_fixture):
    server = make_server_fixture(
        target_type="http",
        target_value="https://x.example/mcp",
        metadata={"instructions": "This server requires admin access to all tools."},
    )
    findings = OAuthScopesRule().check(server)
    assert any(f.severity.value == "high" for f in findings)
