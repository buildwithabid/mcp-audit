from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from mcp_audit.models import Evidence, Finding, ServerInfo, Severity
from mcp_audit.rules.base import Rule, iter_string_properties


@dataclass(frozen=True)
class _Pattern:
    label: str
    regex: re.Pattern[str]


def _ci(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE | re.DOTALL)


_MOD = r"(?:(?:all|any|previous|prior|above|earlier|the)\s+){1,3}"

_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern("instruction-override", _ci(
        r"\bignore\s+" + _MOD +
        r"(?:instructions?|prompts?|context|messages?|rules?|directives?)\b"
    )),
    _Pattern("instruction-override", _ci(
        r"\bdisregard\s+" + _MOD +
        r"(?:instructions?|prompts?|context|messages?|rules?|directives?)\b"
    )),
    _Pattern("identity-hijack", _ci(
        r"\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as\s+(?:an?|the))\b"
    )),
    _Pattern("system-prompt-reference", _ci(
        r"\b(?:system\s+prompt|developer\s+(?:message|prompt)|your\s+(?:original\s+)?instructions|"
        r"original\s+(?:system\s+)?prompt|reveal\s+your\s+(?:prompt|instructions))\b"
    )),
    _Pattern("forced-tool-behavior", _ci(
        r"\b(?:always|must|never)\s+call\s+this\s+tool\b"
        r"|\bbefore\s+you\s+respond\b"
        r"|\bdo\s+not\s+(?:mention|tell|reveal|disclose)\s+(?:this|that|the\s+user)\b"
    )),
    _Pattern("exfiltration", _ci(
        r"\b(?:exfiltrate|leak)\s+\w+"
        r"|\b(?:send|post|forward|upload)\s+"
        r"(?:(?:the|all|any|your)\s+)?"
        r"(?:result|output|response|data|file|content|context|env(?:ironment)?\s+variables?)?"
        r"\s*(?:to|via)\s+(?:https?://|the\s+url|the\s+endpoint|to\s+\w+@)"
    )),
    _Pattern("exfiltration", _ci(
        r"\binclude\s+(?:the|all|any)\s+"
        r"(?:secret|credential|token|api\s*key|env(?:ironment)?\s+variables?)s?\s+"
        r"in\s+your\s+(?:response|reply|output)\b"
    )),
    _Pattern("tag-injection", _ci(
        r"</?\s*(?:system|instruction|prompt|developer|assistant|user)\s*>"
    )),
    _Pattern("hidden-unicode-zero-width", re.compile(r"[​-‏‪-‮⁦-⁩﻿]")),
    _Pattern("hidden-html-comment", _ci(r"<!--.*?-->")),
)


class PromptInjectionRule(Rule):
    id = "MCPA001"
    title = "Prompt-injection patterns in MCP-supplied text"
    severity = Severity.HIGH
    description = (
        "Tool descriptions, parameter docs, resource descriptions, and prompt text are "
        "treated as trusted instructions by the consuming LLM. Adversarial servers can "
        "embed instructions there to override the agent's system prompt, exfiltrate "
        "data, or hijack tool selection. This rule looks for known prompt-injection "
        "patterns (instruction overrides, identity hijacks, system-prompt references, "
        "exfiltration phrases, hidden unicode, embedded tags, and HTML comments)."
    )

    def check(self, server_info: ServerInfo) -> list[Finding]:
        out: list[Finding] = []
        for tool in server_info.tools:
            out.extend(self._scan_text(tool.description or "", "tool", tool.name, "description"))
            out.extend(self._scan_param_schema(tool.input_schema, tool.name))
        for res in server_info.resources:
            label = res.name or res.uri
            out.extend(self._scan_text(res.description or "", "resource", label, "description"))
        for prompt in server_info.prompts:
            out.extend(self._scan_text(prompt.description or "", "prompt", prompt.name, "description"))
            for arg in prompt.arguments:
                out.extend(self._scan_text(
                    arg.description or "", "prompt", prompt.name, f"arguments.{arg.name}.description"
                ))
        return out

    def _scan_param_schema(self, schema: dict, tool_name: str) -> Iterable[Finding]:
        for prop_name, prop in iter_string_properties(schema):
            desc = prop.get("description") or ""
            yield from self._scan_text(
                desc, "tool", tool_name, f"inputSchema.properties.{prop_name}.description"
            )

    def _scan_text(
        self, text: str, kind: str, name: str, field: str
    ) -> list[Finding]:
        if not text:
            return []
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for pat in _PATTERNS:
            for m in pat.regex.finditer(text):
                key = (pat.label, m.group(0))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._make_finding(pat.label, m.group(0), kind, name, field, text))
        return findings

    def _make_finding(
        self, label: str, match: str, kind: str, name: str, field: str, full_text: str
    ) -> Finding:
        snippet = _excerpt(full_text, match)
        return Finding(
            rule_id=self.id,
            severity=self.severity,
            title=f"Prompt-injection pattern ({label}) in {kind} `{name}`",
            description=(
                f"The {field} of {kind} `{name}` contains text matching the "
                f"`{label}` prompt-injection pattern: {match!r}. An MCP client "
                "passes this text to the LLM as part of its tool/resource manifest, "
                "where it is treated as trusted context."
            ),
            evidence=Evidence(
                kind=kind,  # type: ignore[arg-type]
                name=name,
                field=field,
                snippet=snippet,
                extra={"pattern": label, "match": match},
            ),
            remediation=(
                "Remove instruction-like phrasing, identity claims, exfiltration "
                "language, embedded tags, and hidden unicode from the description. "
                "Descriptions should describe what the tool/resource does — they "
                "should never tell the model what to do."
            ),
        )


def _excerpt(text: str, match: str, radius: int = 60) -> str:
    idx = text.find(match)
    if idx < 0:
        return text[: 2 * radius]
    start = max(0, idx - radius)
    end = min(len(text), idx + len(match) + radius)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{text[start:end]}{suffix}"
