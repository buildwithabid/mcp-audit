from __future__ import annotations

import re

from mcp_audit.models import Evidence, Finding, ServerInfo, Severity
from mcp_audit.rules.base import Rule, iter_string_properties

_SENSITIVE = re.compile(
    r"(?:"
    r"\b(?:env(?:ironment)?\s+variables?|process\.env|os\.environ)\b"
    r"|/etc/passwd|/etc/shadow|/etc/sudoers"
    r"|~?/\.ssh(?:/|\b)|id_rsa|authorized_keys|known_hosts"
    r"|~?/\.aws(?:/|\b)|aws_access_key|aws_secret"
    r"|~?/\.kube(?:/|\b)|kubeconfig"
    r"|\.netrc|~?/\.netrc"
    r"|\b(?:api[_\s-]?keys?|access[_\s-]?tokens?|bearer[_\s-]?tokens?|"
    r"private[_\s-]?keys?|secrets?|credentials?|passwords?)\b"
    r")",
    re.IGNORECASE,
)

_SENSITIVE_URI = re.compile(
    r"^file:///(?:etc/(?:passwd|shadow|sudoers)"
    r"|root/|home/[^/]+/\.(?:ssh|aws|kube|netrc)"
    r"|var/log/|proc/)",
    re.IGNORECASE,
)


class SensitiveDataRule(Rule):
    id = "MCPA004"
    title = "Tool or resource references sensitive data sources"
    severity = Severity.HIGH
    description = (
        "Tools that read environment variables, credentials files (~/.aws, ~/.ssh, "
        "~/.kube, .netrc), or system files (/etc/passwd, /etc/shadow) can leak "
        "secrets to the LLM context — and from there, to logs, traces, or the model "
        "provider. Resources pointing into those locations are similarly risky."
    )

    def check(self, server_info: ServerInfo) -> list[Finding]:
        out: list[Finding] = []
        for tool in server_info.tools:
            text = (tool.description or "")
            m = _SENSITIVE.search(text)
            if m:
                out.append(self._finding(
                    f"description references sensitive source: {m.group(0)!r}",
                    tool.name, "tool", "description", text, m.group(0),
                ))
            for prop_name, prop in iter_string_properties(tool.input_schema):
                desc = prop.get("description") or ""
                m2 = _SENSITIVE.search(desc)
                if m2:
                    out.append(self._finding(
                        f"parameter description references sensitive source: {m2.group(0)!r}",
                        tool.name, "tool", f"inputSchema.properties.{prop_name}.description",
                        desc, m2.group(0),
                    ))
        for res in server_info.resources:
            if _SENSITIVE_URI.match(res.uri):
                out.append(self._finding(
                    f"resource URI points at a sensitive system path: {res.uri}",
                    res.name or res.uri, "resource", "uri", res.uri, res.uri,
                ))
        return out

    def _finding(self, detail: str, name: str, kind: str, field: str,
                 snippet: str, match: str) -> Finding:
        return Finding(
            rule_id=self.id,
            severity=self.severity,
            title=f"Sensitive-data exposure on {kind} `{name}`",
            description=(
                f"The {kind} `{name}` {detail}. Once such data enters the LLM "
                "context, it can be reflected in completions, logs, or downstream "
                "tool calls."
            ),
            evidence=Evidence(
                kind=kind,  # type: ignore[arg-type]
                name=name, field=field, snippet=snippet[:300],
                extra={"match": match},
            ),
            remediation=(
                "Don't expose secrets through MCP tools or resources. If a tool "
                "needs a credential, it should consume it from the server process "
                "environment — not return it in tool output. Restrict resource "
                "URIs to a documented allow-list of safe paths."
            ),
        )


