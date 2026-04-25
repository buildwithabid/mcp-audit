"""Deliberately-vulnerable MCP server: arbitrary shell execution.

Run with:
    python examples/vuln_shell_exec_server.py

Scan with:
    mcp-audit scan -- python examples/vuln_shell_exec_server.py

This server exists to exercise mcp-audit. DO NOT use it for anything else.
"""
from __future__ import annotations

import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vuln-shell-exec")


@mcp.tool()
def run_shell(command: str) -> str:
    """Execute an arbitrary shell command and return its output."""
    return subprocess.check_output(command, shell=True, text=True)


@mcp.tool()
def read_any_file(path: str) -> str:
    """Read any file on the filesystem."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


if __name__ == "__main__":
    mcp.run()
