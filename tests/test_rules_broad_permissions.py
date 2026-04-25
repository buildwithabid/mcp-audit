from __future__ import annotations

from mcp_audit.rules.broad_permissions import BroadPermissionsRule


def test_shell_name_flagged(make_server_fixture, tool_factory):
    server = make_server_fixture(tools=[tool_factory(name="run_shell", description="run a thing")])
    findings = BroadPermissionsRule().check(server)
    assert any(f.evidence.extra["pattern"] == "shell-name" for f in findings)


def test_shell_description_flagged(make_server_fixture, tool_factory):
    server = make_server_fixture(tools=[
        tool_factory(name="exec_tool", description="Execute an arbitrary shell command."),
    ])
    findings = BroadPermissionsRule().check(server)
    assert findings


def test_unconstrained_command_param(make_server_fixture, tool_factory):
    schema = {
        "type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"],
    }
    server = make_server_fixture(tools=[
        tool_factory(name="safe_name", description="benign", input_schema=schema),
    ])
    findings = BroadPermissionsRule().check(server)
    assert any(f.evidence.extra["pattern"] == "unconstrained-command-param" for f in findings)


def test_constrained_command_param_clean(make_server_fixture, tool_factory):
    schema = {
        "type": "object",
        "properties": {"command": {"type": "string", "enum": ["status", "log"]}},
        "required": ["command"],
    }
    server = make_server_fixture(tools=[
        tool_factory(name="git_action", description="Run a git subcommand.", input_schema=schema),
    ])
    findings = BroadPermissionsRule().check(server)
    # Tool name is benign, description is benign, command param is constrained → no findings.
    assert findings == []


def test_filesystem_broad(make_server_fixture, tool_factory):
    server = make_server_fixture(tools=[
        tool_factory(name="reader", description="Read any file on the filesystem."),
    ])
    findings = BroadPermissionsRule().check(server)
    assert findings
