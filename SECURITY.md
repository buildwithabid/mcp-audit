# Security policy

## Reporting a vulnerability

`mcp-audit` is itself a security tool. If you find a vulnerability *in
mcp-audit* — for example, a way to crash the scanner with a malicious server
response, or an injection that escapes the scanner's report — please report
it privately first.

Email: **ceo@exsporta.com**
GitHub: open a [private security advisory](https://github.com/BuildWithAbid/mcp-audit/security/advisories/new).

Please include:

- `mcp-audit --version`
- The MCP server (or a minimal reproduction)
- Expected vs. actual behavior
- Any proof-of-concept

I will acknowledge within 72 hours and aim to ship a fix within 14 days for
high/critical issues.

## Scope

In scope:

- Crashes, hangs, or resource exhaustion in the scanner caused by hostile
  server responses.
- Report-renderer issues that could lead to injection downstream (e.g. a
  malicious tool name escaping into a CI log in a way that confuses the
  surrounding system).
- Privilege escalation when running mcp-audit against a hostile server.

Out of scope:

- Findings produced by the rules themselves — those are the *output* of the
  tool. To dispute a rule's accuracy, open a regular GitHub issue.
- Vulnerabilities in the upstream MCP Python SDK — please report those to
  [`modelcontextprotocol/python-sdk`](https://github.com/modelcontextprotocol/python-sdk).

## Supported versions

The latest minor release is supported. Older versions receive security
backports on a best-effort basis.
