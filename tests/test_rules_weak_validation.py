from __future__ import annotations

from mcp_audit.rules.weak_validation import WeakValidationRule


def test_unconstrained_string(make_server_fixture, tool_factory):
    schema = {
        "type": "object",
        "properties": {"q": {"type": "string"}},
        "required": ["q"],
        "additionalProperties": False,
    }
    server = make_server_fixture(tools=[tool_factory(input_schema=schema)])
    findings = WeakValidationRule().check(server)
    assert any("unconstrained-string:q" in f.evidence.extra["issue"] for f in findings)


def test_no_required(make_server_fixture, tool_factory):
    schema = {
        "type": "object",
        "properties": {"q": {"type": "string", "maxLength": 100}},
        "additionalProperties": False,
    }
    server = make_server_fixture(tools=[tool_factory(input_schema=schema)])
    findings = WeakValidationRule().check(server)
    assert any(f.evidence.extra["issue"] == "no-required-fields" for f in findings)


def test_additional_properties_allowed(make_server_fixture, tool_factory):
    schema = {
        "type": "object",
        "properties": {"q": {"type": "string", "maxLength": 100}},
        "required": ["q"],
    }
    server = make_server_fixture(tools=[tool_factory(input_schema=schema)])
    findings = WeakValidationRule().check(server)
    assert any(f.evidence.extra["issue"] == "permits-additional-properties" for f in findings)


def test_well_formed_schema_clean(make_server_fixture, tool_factory):
    schema = {
        "type": "object",
        "properties": {
            "q": {"type": "string", "maxLength": 200, "pattern": "^[a-z]+$"},
        },
        "required": ["q"],
        "additionalProperties": False,
    }
    server = make_server_fixture(tools=[tool_factory(input_schema=schema)])
    assert WeakValidationRule().check(server) == []
