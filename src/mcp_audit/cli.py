from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from mcp_audit import __version__
from mcp_audit.models import Severity
from mcp_audit.report import exit_code, render_json, render_markdown
from mcp_audit.rules import all_rule_classes
from mcp_audit.scanner import detect_target, fetch_server_info, parse_stdio_command, run_rules

app = typer.Typer(
    name="mcp-audit",
    help="Security scanner for MCP (Model Context Protocol) servers.",
    add_completion=False,
)

_stderr = Console(stderr=True)
_stdout = Console()


def _parse_kv(items: list[str], sep: str, label: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in items:
        if sep not in raw:
            raise typer.BadParameter(f"{label} must be in `KEY{sep}VALUE` form, got: {raw!r}")
        key, _, value = raw.partition(sep)
        out[key.strip()] = value.lstrip()
    return out


def _parse_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        valid = ", ".join(s.value for s in Severity)
        raise typer.BadParameter(f"invalid severity {value!r}; expected one of: {valid}")


@app.command()
def scan(
    server: Annotated[
        list[str],
        typer.Argument(
            help="URL of an HTTP MCP server, or (after `--`) a stdio command.",
            metavar="SERVER",
        ),
    ],
    header: Annotated[
        list[str],
        typer.Option("--header", "-H", help="HTTP header for remote servers (repeatable)."),
    ] = [],
    env: Annotated[
        list[str],
        typer.Option("--env", "-e", help="Env var for stdio servers, KEY=VAL (repeatable)."),
    ] = [],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit a JSON report instead of Markdown."),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write report to this file instead of stdout."),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit non-zero if any finding has severity >= this. "
                 "One of: info, low, medium, high, critical.",
        ),
    ] = "high",
) -> None:
    """Scan an MCP server and produce a security report.

    Examples:

      mcp-audit scan https://example.com/mcp

      mcp-audit scan -- python server.py --foo bar

      mcp-audit scan --json -o report.json -- npx -y @modelcontextprotocol/server-everything
    """
    if not server:
        raise typer.BadParameter("missing server (URL or stdio command)")

    threshold = _parse_severity(fail_on)
    headers = _parse_kv(header, ":", "--header")
    env_dict = _parse_kv(env, "=", "--env")

    if len(server) == 1 and server[0].startswith(("http://", "https://")):
        target = detect_target(server[0])
        command, args = None, None
    else:
        command, args = parse_stdio_command(server)
        target = detect_target(" ".join(server))

    _stderr.print(f"[dim]mcp-audit {__version__} · scanning {target.type} target…[/dim]")

    try:
        server_info = asyncio.run(
            fetch_server_info(target, env=env_dict or None, headers=headers or None,
                              command=command, args=args)
        )
    except Exception as exc:
        _stderr.print(f"[red]error:[/red] could not connect to MCP server: {exc}")
        raise typer.Exit(code=2)

    findings = run_rules(server_info)
    text = render_json(findings, target) if json_output else render_markdown(findings, target)

    if output:
        output.write_text(text, encoding="utf-8")
        _stderr.print(f"[dim]report written to {output}[/dim]")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")

    code = exit_code(findings, threshold)
    if code != 0:
        _stderr.print(
            f"[yellow]found {sum(1 for f in findings if f.severity >= threshold)} "
            f"finding(s) at severity >= {threshold.value}[/yellow]"
        )
    raise typer.Exit(code=code)


@app.command("list-rules")
def list_rules(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List all built-in rules."""
    rule_classes = all_rule_classes()
    if json_output:
        payload = [
            {"id": c.id, "title": c.title, "severity": c.severity.value, "description": c.description}
            for c in rule_classes
        ]
        _stdout.print_json(data=payload)
        return

    if not rule_classes:
        _stdout.print("[yellow]no rules registered[/yellow]")
        return

    for c in rule_classes:
        _stdout.print(f"[bold]{c.id}[/bold]  [magenta]{c.severity.value}[/magenta]  {c.title}")
        _stdout.print(f"  [dim]{c.description}[/dim]")
        _stdout.print()


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option("--version", "-V", help="Show version and exit.", is_eager=True),
    ] = False,
) -> None:
    if version:
        _stdout.print(f"mcp-audit {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        _stdout.print(ctx.get_help())
        raise typer.Exit()


if __name__ == "__main__":
    app()
