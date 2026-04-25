from __future__ import annotations

from mcp_audit.models import Evidence, Finding, ServerInfo, Severity
from mcp_audit.rules.base import Rule


class OAuthScopesRule(Rule):
    id = "MCPA006"
    title = "Remote server auth/scope hygiene"
    severity = Severity.LOW
    description = (
        "For remote (HTTP/Streamable HTTP) MCP servers, an audit should look at the "
        "auth posture: were credentials required, and what scopes does the server "
        "imply it can act on. The MCP Python SDK does not currently expose a "
        "scope-aware client API, so this rule reports informational signals only "
        "and flags obviously over-broad scope claims when servers publish them in "
        "their initialize metadata or instructions."
    )

    def check(self, server_info: ServerInfo) -> list[Finding]:
        if server_info.target.type != "http":
            return []

        out: list[Finding] = []
        metadata = server_info.server_metadata or {}
        instructions = (metadata.get("instructions") or "").lower() if isinstance(
            metadata.get("instructions"), str
        ) else ""

        if not instructions and not metadata.get("capabilities"):
            out.append(Finding(
                rule_id=self.id,
                severity=Severity.INFO,
                title="Remote server published no auth/scope metadata",
                description=(
                    "The remote MCP server returned no instructions or capability "
                    "metadata describing what authority it acts with. This is "
                    "informational — verify the server's auth model out-of-band."
                ),
                evidence=Evidence(
                    kind="server", name=server_info.target.value, field=None,
                    snippet=None, extra={"metadata": metadata},
                ),
                remediation=(
                    "Document the server's auth model and required scopes in its "
                    "README. Prefer per-action scopes (least privilege) over a "
                    "single broad token."
                ),
            ))

        for keyword in ("admin", "all scopes", "full access", "wildcard scope", "scope: *", "*:*"):
            if keyword in instructions:
                out.append(Finding(
                    rule_id=self.id,
                    severity=Severity.HIGH,
                    title="Remote server claims a broad/admin scope",
                    description=(
                        f"The server's published instructions reference a broad "
                        f"scope: {keyword!r}. Broad scopes turn any server "
                        "compromise into a privileged compromise."
                    ),
                    evidence=Evidence(
                        kind="server", name=server_info.target.value,
                        field="instructions", snippet=instructions[:300],
                        extra={"keyword": keyword},
                    ),
                    remediation=(
                        "Issue per-action scopes. Avoid `*`, `admin`, or `all` "
                        "scopes. Document scope-to-tool mapping."
                    ),
                ))

        return out
