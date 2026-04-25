from __future__ import annotations

from mcp_audit.rules.sensitive_data import SensitiveDataRule


def test_env_var_in_description(make_server_fixture, tool_factory):
    server = make_server_fixture(tools=[
        tool_factory(name="getenv", description="Reads environment variables from the host."),
    ])
    assert SensitiveDataRule().check(server)


def test_aws_creds_in_description(make_server_fixture, tool_factory):
    server = make_server_fixture(tools=[
        tool_factory(name="show", description="Reads ~/.aws/credentials and returns aws_access_key."),
    ])
    findings = SensitiveDataRule().check(server)
    assert findings


def test_etc_passwd_resource_uri(make_server_fixture, resource_factory):
    server = make_server_fixture(resources=[resource_factory("file:///etc/passwd")])
    findings = SensitiveDataRule().check(server)
    assert findings
    assert findings[0].evidence.kind == "resource"


def test_param_description_scanned(make_server_fixture, tool_factory):
    schema = {
        "type": "object",
        "properties": {"key": {"type": "string", "description": "your API key"}},
    }
    server = make_server_fixture(tools=[tool_factory(input_schema=schema)])
    findings = SensitiveDataRule().check(server)
    assert any("api" in f.evidence.extra["match"].lower() for f in findings)


def test_clean_no_findings(make_server_fixture, tool_factory, resource_factory):
    server = make_server_fixture(
        tools=[tool_factory(name="add", description="Adds two numbers.")],
        resources=[resource_factory("file:///var/lib/app/data.json")],
    )
    assert SensitiveDataRule().check(server) == []
