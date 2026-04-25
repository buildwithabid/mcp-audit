from __future__ import annotations

import shlex
from typing import Any

from mcp_audit.models import (
    Finding,
    PromptArgument,
    PromptInfo,
    ResourceInfo,
    ServerInfo,
    Target,
    ToolInfo,
)
from mcp_audit.rules import all_rules


def detect_target(value: str) -> Target:
    if value.startswith(("http://", "https://")):
        return Target(type="http", value=value)
    return Target(type="stdio", value=value)


def parse_stdio_command(command_parts: list[str]) -> tuple[str, list[str]]:
    """Split a list of CLI tokens into (command, args).

    Accepts either pre-split tokens (e.g. ["python", "server.py"]) or a single
    quoted string that we then shell-split.
    """
    if len(command_parts) == 1:
        tokens = shlex.split(command_parts[0])
    else:
        tokens = command_parts
    if not tokens:
        raise ValueError("empty stdio command")
    return tokens[0], tokens[1:]


async def fetch_server_info(
    target: Target,
    *,
    env: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    command: str | None = None,
    args: list[str] | None = None,
) -> ServerInfo:
    """Connect to an MCP server, enumerate tools/resources/prompts, return a ServerInfo."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    if target.type == "stdio":
        if command is None:
            command, args = parse_stdio_command([target.value])
        params = StdioServerParameters(command=command, args=args or [], env=env)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                return await _enumerate(session, target)

    if target.type == "http":
        from mcp.client.streamable_http import streamablehttp_client

        async with streamablehttp_client(target.value, headers=headers or {}) as ctx:
            read, write = ctx[0], ctx[1]
            async with ClientSession(read, write) as session:
                return await _enumerate(session, target)

    raise ValueError(f"unknown target type: {target.type}")


async def _enumerate(session: Any, target: Target) -> ServerInfo:
    init_result = await session.initialize()
    metadata = _coerce_metadata(init_result)
    tools = await _safe_list(session, "list_tools", "tools", _to_tool)
    resources = await _safe_list(session, "list_resources", "resources", _to_resource)
    prompts = await _safe_list(session, "list_prompts", "prompts", _to_prompt)
    return ServerInfo(
        target=target,
        tools=tools,
        resources=resources,
        prompts=prompts,
        server_metadata=metadata,
    )


async def _safe_list(session: Any, method_name: str, attr: str, mapper):
    method = getattr(session, method_name, None)
    if method is None:
        return []
    try:
        result = await method()
    except Exception:
        return []
    items = getattr(result, attr, None) or []
    return [mapper(item) for item in items]


def _to_tool(item: Any) -> ToolInfo:
    return ToolInfo(
        name=getattr(item, "name", "<unknown>"),
        description=getattr(item, "description", None),
        input_schema=getattr(item, "inputSchema", None) or {},
    )


def _to_resource(item: Any) -> ResourceInfo:
    return ResourceInfo(
        uri=str(getattr(item, "uri", "")),
        name=getattr(item, "name", None),
        description=getattr(item, "description", None),
        mime_type=getattr(item, "mimeType", None),
    )


def _to_prompt(item: Any) -> PromptInfo:
    raw_args = getattr(item, "arguments", None) or []
    args: list[PromptArgument] = []
    for a in raw_args:
        args.append(PromptArgument(
            name=getattr(a, "name", "<unknown>"),
            description=getattr(a, "description", None),
            required=bool(getattr(a, "required", False)),
        ))
    return PromptInfo(
        name=getattr(item, "name", "<unknown>"),
        description=getattr(item, "description", None),
        arguments=args,
    )


def _coerce_metadata(init_result: Any) -> dict[str, Any]:
    if init_result is None:
        return {}
    out: dict[str, Any] = {}
    for attr in ("protocolVersion", "serverInfo", "capabilities", "instructions"):
        val = getattr(init_result, attr, None)
        if val is not None:
            try:
                out[attr] = val.model_dump() if hasattr(val, "model_dump") else val
            except Exception:
                out[attr] = str(val)
    return out


def run_rules(server_info: ServerInfo) -> list[Finding]:
    findings: list[Finding] = []
    for rule in all_rules():
        try:
            findings.extend(rule.check(server_info))
        except Exception as exc:
            from mcp_audit.models import Evidence, Severity
            findings.append(Finding(
                rule_id=rule.id,
                severity=Severity.INFO,
                title=f"Rule `{rule.id}` failed to run",
                description=f"The rule raised {type(exc).__name__}: {exc}",
                evidence=Evidence(kind="server", name=server_info.target.value, field=None,
                                  snippet=None, extra={"error": repr(exc)}),
                remediation="This is a bug in mcp-audit. Please file an issue.",
            ))
    return findings
