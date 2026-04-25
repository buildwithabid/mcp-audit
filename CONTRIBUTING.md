# Contributing to mcp-audit

Thanks for considering a contribution. The most useful contributions are:

1. **New rules** — see [RULES.md](RULES.md) and the existing rules in
   [`src/mcp_audit/rules/`](src/mcp_audit/rules/) for the pattern. Each rule
   lives in its own ~30-line file.
2. **Real-world false negatives** — if you find an MCP server that should
   trigger a finding but doesn't, please open an issue with the server's tool
   manifest (or a link to its source).
3. **Real-world false positives** — same idea, but for findings that are
   noise. Include the rule ID and the manifest snippet.
4. **Better remediation guidance** — if a rule's remediation text is vague,
   PRs welcome.

## Local setup

```bash
git clone https://github.com/BuildWithAbid/mcp-audit
cd mcp-audit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Adding a rule

1. Create `src/mcp_audit/rules/<your_rule>.py`. The class must inherit from
   `Rule`, set `id`, `title`, `severity`, `description`, and implement
   `check(server_info) -> list[Finding]`. The registry auto-discovers it.
2. Add tests in `tests/test_rules_<your_rule>.py`. Use the
   `make_server_fixture`, `tool_factory`, `resource_factory`, and
   `prompt_factory` fixtures from `conftest.py`.
3. Add an entry to [RULES.md](RULES.md) explaining the rationale and
   linking to the relevant OWASP MCP Top 10 item if applicable.
4. Bump severity conservatively. Prefer `medium` for first releases of a
   rule unless there is a clear, exploitable vulnerability behind it.

## Style

- Python 3.11+, type-annotated.
- `ruff` for linting (`ruff check src tests`).
- Keep rules pure inspection — no I/O, no async. The scanner phase
  produces a fully-populated `ServerInfo` before any rule runs.
- Keep evidence specific: include the field name (`description`,
  `inputSchema.properties.x.description`) and a short snippet.

## Pull requests

- One rule, one fix, or one feature per PR. Smaller is better.
- Add or update tests.
- Update `RULES.md` if you add or change a rule.
- The CI matrix runs against Python 3.11, 3.12, and 3.13.

By contributing, you agree that your contributions will be licensed under
the project's MIT license.
