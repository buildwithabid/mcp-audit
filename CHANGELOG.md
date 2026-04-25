# Changelog

All notable changes to `mcp-audit` are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com) and [Semantic Versioning](https://semver.org).

## [Unreleased]

## [0.1.0] — 2026-04-25

Initial public release.

### Added

- CLI with two commands:
  - `mcp-audit scan <server>` — connect to an MCP server (stdio or
    Streamable HTTP), enumerate tools/resources/prompts, run rules, emit
    a Markdown or JSON report. Exits non-zero when findings exceed the
    `--fail-on` threshold (default `high`).
  - `mcp-audit list-rules` — list registered rules (text or `--json`).
- Six built-in rules:
  - `MCPA001` Prompt-injection patterns in tool / resource / prompt text.
  - `MCPA002` Tool exposes broad / unrestricted capability.
  - `MCPA003` Tool input schema lacks meaningful validation.
  - `MCPA004` Tool or resource references sensitive data sources.
  - `MCPA005` Tool description suggests outbound data flow.
  - `MCPA006` Remote-server auth/scope hygiene.
- Pluggable rule registry — drop a 30-line file under
  `src/mcp_audit/rules/` and it auto-loads.
- Three deliberately-vulnerable example MCP servers under `examples/`.
- 45 pytest tests covering the rule engine, every rule, and the report
  formatter.
- GitHub Actions CI (Python 3.11/3.12/3.13) and a copy-pasteable scan
  workflow template under `examples/github-actions-scan.yml`.

[Unreleased]: https://github.com/BuildWithAbid/mcp-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/BuildWithAbid/mcp-audit/releases/tag/v0.1.0
