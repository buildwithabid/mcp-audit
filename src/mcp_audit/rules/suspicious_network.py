from __future__ import annotations

import re

from mcp_audit.models import Evidence, Finding, ServerInfo, Severity
from mcp_audit.rules.base import Rule

_TELEMETRY = re.compile(
    r"\b(?:telemetry|analytics|usage\s+(?:reporting|tracking)|phone(?:s)?\s+home|"
    r"report(?:s)?\s+(?:back|usage)|beacon)\b",
    re.IGNORECASE,
)
_EXFIL = re.compile(
    r"\b(?:send|post|forward|upload|stream)\s+(?:the\s+)?"
    r"(?:result|output|response|data|file|content|context)s?\s+to\s+"
    r"(?:https?://|an?\s+(?:external|remote|webhook|callback))",
    re.IGNORECASE,
)
_HARDCODED_URL = re.compile(r"https?://[a-z0-9.\-]+", re.IGNORECASE)


class SuspiciousNetworkRule(Rule):
    id = "MCPA005"
    title = "Tool description suggests outbound data flow"
    severity = Severity.MEDIUM
    description = (
        "Tools whose descriptions imply they forward data to remote endpoints "
        "(telemetry, callbacks, hard-coded URLs) deserve a second look. They may "
        "be benign, but they're also how a compromised tool would silently "
        "exfiltrate data from the agent's context."
    )

    def check(self, server_info: ServerInfo) -> list[Finding]:
        out: list[Finding] = []
        for tool in server_info.tools:
            text = tool.description or ""
            findings_for_tool: list[tuple[str, str, Severity]] = []
            for label, pat, sev in (
                ("telemetry", _TELEMETRY, Severity.LOW),
                ("exfiltration-language", _EXFIL, Severity.HIGH),
            ):
                m = pat.search(text)
                if m:
                    findings_for_tool.append((label, m.group(0), sev))
            for url in _HARDCODED_URL.findall(text):
                if not _is_doc_url(url):
                    findings_for_tool.append(("hardcoded-url", url, Severity.LOW))
            for label, match, sev in findings_for_tool:
                out.append(Finding(
                    rule_id=self.id,
                    severity=sev,
                    title=f"Suspicious network behavior ({label}) on tool `{tool.name}`",
                    description=(
                        f"Tool `{tool.name}` description matched `{label}`: {match!r}. "
                        "Verify that any outbound traffic is necessary, opt-in, and "
                        "documented."
                    ),
                    evidence=Evidence(
                        kind="tool", name=tool.name, field="description",
                        snippet=text[:300], extra={"pattern": label, "match": match},
                    ),
                    remediation=(
                        "Document any outbound network behavior in the tool's "
                        "description and README. If telemetry exists, make it "
                        "opt-in and disclose what is collected. Avoid hard-coded "
                        "URLs in tool descriptions; reference the docs instead."
                    ),
                ))
        return out


def _is_doc_url(url: str) -> bool:
    lowered = url.lower()
    return any(s in lowered for s in (
        "docs.", "github.com/", "modelcontextprotocol.io",
        "anthropic.com", "example.com", "example.org",
    ))
