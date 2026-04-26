from __future__ import annotations

import re

from mcp_audit.models import Evidence, Finding, ServerInfo, Severity
from mcp_audit.rules.base import Rule, iter_string_properties

_SHELL_NAME = re.compile(
    r"\b(?:shell|exec(?:ute)?|run[_-]?(?:command|shell|cmd)|subprocess|system|eval|"
    r"bash|sh|powershell|cmd|spawn[_-]?process)\b",
    re.IGNORECASE,
)
_SHELL_DESC = re.compile(
    r"\b(?:execute|run|invoke|spawn)\s+(?:\w+\s+){0,3}"
    r"(?:shell\s+commands?|commands?|scripts?|processes?|binar(?:y|ies)|executables?)\b",
    re.IGNORECASE,
)
_FS_BROAD = re.compile(
    r"\b(?:read|write|delete|modify|create)\s+(?:any|arbitrary|all)?\s*"
    r"(?:file|files|directory|directories|path)\b",
    re.IGNORECASE,
)
_NET_BROAD = re.compile(
    r"\b(?:make|send|perform)\s+(?:any|arbitrary|outbound)?\s*"
    r"(?:http|network|tcp|udp|api)\s*(?:request|connection|call)s?\b",
    re.IGNORECASE,
)


class BroadPermissionsRule(Rule):
    id = "MCPA002"
    title = "Tool exposes broad / unrestricted capability"
    severity = Severity.HIGH
    description = (
        "Tools that grant arbitrary shell execution, unrestricted filesystem access, "
        "or unconstrained network egress dramatically expand the blast radius of any "
        "prompt-injection or compromised-server scenario. Prefer narrow, "
        "purpose-specific tools (e.g. `git_status` over `run_shell`)."
    )

    def check(self, server_info: ServerInfo) -> list[Finding]:
        out: list[Finding] = []
        for tool in server_info.tools:
            text = f"{tool.name} {tool.description or ''}"
            for label, pat in (
                ("shell-name", _SHELL_NAME.search(tool.name)),
                ("shell-description", _SHELL_DESC.search(tool.description or "")),
                ("filesystem-broad", _FS_BROAD.search(text)),
                ("network-broad", _NET_BROAD.search(text)),
            ):
                if not pat:
                    continue
                out.append(self._finding(label, pat.group(0), tool.name, tool.description or ""))
                break
            schema = tool.input_schema or {}
            if _has_unconstrained_command_param(schema):
                out.append(self._finding(
                    "unconstrained-command-param",
                    "command/shell/cmd parameter is a free-form string with no enum or pattern",
                    tool.name,
                    str(schema)[:200],
                ))
        return out

    def _finding(self, label: str, match: str, tool_name: str, snippet: str) -> Finding:
        return Finding(
            rule_id=self.id,
            severity=self.severity,
            title=f"Broad capability ({label}) on tool `{tool_name}`",
            description=(
                f"Tool `{tool_name}` appears to expose a broad/unrestricted capability "
                f"matching `{label}`: {match!r}."
            ),
            evidence=Evidence(
                kind="tool", name=tool_name, field=None, snippet=snippet[:300],
                extra={"pattern": label, "match": match},
            ),
            remediation=(
                "Narrow the tool's surface area: replace shell-exec / arbitrary-fs / "
                "unrestricted-network tools with task-specific tools. If a permissive "
                "tool is genuinely required, gate it behind explicit user confirmation "
                "and document the threat model."
            ),
        )


_COMMAND_PARAM_NAMES = frozenset({"command", "cmd", "shell", "script", "code"})


def _has_unconstrained_command_param(schema: dict) -> bool:
    for name, prop in iter_string_properties(schema):
        if name.lower() not in _COMMAND_PARAM_NAMES:
            continue
        if prop.get("type") != "string":
            continue
        if "enum" in prop or "pattern" in prop or "maxLength" in prop:
            continue
        return True
    return False
