from __future__ import annotations

from mcp_audit.models import Evidence, Finding, ServerInfo, Severity
from mcp_audit.rules.base import Rule, iter_string_properties


class WeakValidationRule(Rule):
    id = "MCPA003"
    title = "Tool input schema lacks meaningful validation"
    severity = Severity.MEDIUM
    description = (
        "Tool inputSchemas should narrow what the LLM is allowed to pass: required "
        "fields, length limits, regex patterns, enums, or rejection of additional "
        "properties. Free-form strings with no constraints make injection and misuse "
        "easier and produce ambiguous tool calls."
    )

    def check(self, server_info: ServerInfo) -> list[Finding]:
        out: list[Finding] = []
        for tool in server_info.tools:
            schema = tool.input_schema
            if not isinstance(schema, dict):
                continue
            issues = list(_schema_issues(schema))
            for label, detail in issues:
                out.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    title=f"Weak input validation ({label}) on tool `{tool.name}`",
                    description=(
                        f"Tool `{tool.name}` has an input schema that {detail}. "
                        "Tighter schemas reduce attack surface and make tool calls "
                        "more predictable."
                    ),
                    evidence=Evidence(
                        kind="tool", name=tool.name, field="inputSchema",
                        snippet=str(schema)[:300],
                        extra={"issue": label},
                    ),
                    remediation=(
                        "Add `required`, `maxLength`, `pattern`, or `enum` constraints "
                        "to free-form fields. Set `additionalProperties: false` on "
                        "the top-level object schema."
                    ),
                ))
        return out


def _schema_issues(schema: dict):
    if schema.get("type") != "object":
        return
    if schema.get("additionalProperties") is not False:
        yield "permits-additional-properties", "permits additional properties (set additionalProperties: false)"
    properties = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    if isinstance(properties, dict) and properties and not required:
        yield "no-required-fields", "declares properties but no `required` list"
    for name, prop in iter_string_properties(schema):
        if prop.get("type") != "string":
            continue
        if any(k in prop for k in ("maxLength", "pattern", "enum", "format")):
            continue
        yield (
            f"unconstrained-string:{name}",
            f"property `{name}` is an unconstrained string (no maxLength/pattern/enum/format)",
        )
