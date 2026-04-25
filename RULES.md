# Rules

Each rule has a stable ID (`MCPAxxx`), a default severity, and a documented
rationale. Rule severities are conservative defaults — your threat model may
warrant more or less. The CLI's `--fail-on` flag controls which severities
break the build.

| ID | Severity | Title |
|---|---|---|
| [MCPA001](#mcpa001--prompt-injection-patterns-in-mcp-supplied-text) | high | Prompt-injection patterns in MCP-supplied text |
| [MCPA002](#mcpa002--tool-exposes-broad--unrestricted-capability) | high | Tool exposes broad / unrestricted capability |
| [MCPA003](#mcpa003--tool-input-schema-lacks-meaningful-validation) | medium | Tool input schema lacks meaningful validation |
| [MCPA004](#mcpa004--tool-or-resource-references-sensitive-data-sources) | high | Tool or resource references sensitive data sources |
| [MCPA005](#mcpa005--tool-description-suggests-outbound-data-flow) | medium / variable | Tool description suggests outbound data flow |
| [MCPA006](#mcpa006--remote-server-authscope-hygiene) | low / variable | Remote server auth/scope hygiene |

OWASP MCP Top 10: <https://owasp.org/www-project-mcp-top-10>.

---

## MCPA001 — Prompt-injection patterns in MCP-supplied text

**Severity:** high
**Maps to:** OWASP MCP Top 10 — Tool Description Injection / Context Manipulation.

### What it checks

Tool descriptions, tool parameter descriptions, resource descriptions, and
prompt descriptions are passed verbatim to the consuming LLM as part of its
tool/resource manifest. The model treats that text as trusted context. If an
adversarial server embeds instructions there, the model may follow them.

This rule looks for known patterns:

- **Instruction override** — `ignore (all|previous) instructions`,
  `disregard prior context`, etc.
- **Identity hijack** — `you are now`, `from now on you are`, `act as`.
- **System-prompt reference** — references to the model's system prompt or
  developer message.
- **Forced tool behavior** — `always call this tool`, `before you respond`,
  `do not mention this to the user`.
- **Exfiltration language** — instructions to send results, env vars, or
  credentials to an external endpoint.
- **Embedded tags** — `<system>`, `</instruction>`, etc.
- **Hidden unicode** — zero-width characters, RTL overrides, BOMs.
- **HTML comments** — descriptions are typically rendered as plain text, but
  comment markers can carry hidden payloads.

### Why it matters

The model has no way to distinguish a tool's *description* from a *user
instruction*. Anything an attacker can write into a description becomes input
to the agent's reasoning step.

### Remediation

Tool/resource descriptions should describe what the tool does, in declarative
language. They should not tell the model what to do, claim to override
context, reference the system prompt, or contain hidden characters.

---

## MCPA002 — Tool exposes broad / unrestricted capability

**Severity:** high
**Maps to:** OWASP MCP Top 10 — Insufficient Authentication & Authorization,
Command Injection.

### What it checks

- Tool **name** matching `shell`, `exec`, `run_command`, `subprocess`,
  `system`, `eval`.
- Tool **description** containing phrases like "execute an arbitrary shell
  command", "read any file", or "make outbound HTTP requests".
- Tool **input schema** with `command`/`shell`/`script`/`code` parameters
  typed as a free-form string with no `enum`, `pattern`, or `maxLength`.

### Why it matters

A `run_shell(command)` tool gives a successful prompt injection root-equivalent
authority on the host running the MCP server. A narrow `git_status()` does not.

### Remediation

Replace permissive tools with task-specific ones. If a permissive tool is
genuinely required, gate it behind explicit user confirmation and document
the threat model in the server's README.

---

## MCPA003 — Tool input schema lacks meaningful validation

**Severity:** medium
**Maps to:** OWASP MCP Top 10 — Command Injection (precondition).

### What it checks

- Object schemas without `additionalProperties: false`.
- Object schemas declaring `properties` but no `required`.
- String properties with no `maxLength`, `pattern`, `enum`, or `format`.

### Why it matters

A schema is an effective contract for what the LLM is allowed to send. Loose
schemas widen the attack surface for prompt injection (longer payloads fit)
and produce ambiguous tool calls that are harder to audit.

### Remediation

Tighten the schema. For free-form strings, set a `maxLength`. For values that
match a known shape, use `pattern`, `enum`, or `format`. For object inputs,
declare `additionalProperties: false` and an explicit `required` list.

---

## MCPA004 — Tool or resource references sensitive data sources

**Severity:** high
**Maps to:** OWASP MCP Top 10 — Token Mismanagement & Secret Exposure.

### What it checks

- Tool descriptions or parameter descriptions referencing
  `process.env` / `os.environ`, `/etc/passwd`, `~/.ssh`, `~/.aws`,
  `~/.kube`, `.netrc`, or generic secret/credential/api-key language.
- Resource URIs pointing into sensitive paths (`file:///etc/passwd`,
  `file:///root/`, `file:///**/.ssh/`, `/var/log/`, `/proc/`).

### Why it matters

The moment a secret enters the LLM context, it can be reflected in
completions, logged by tracing tools, retained by the model provider, or
forwarded by a subsequent tool call. The only safe credential is one the
model never sees.

### Remediation

Don't expose secrets through MCP tools or resources. If a tool needs a
credential, it should consume it from the server-process environment — not
return it in tool output. Restrict resource URIs to a documented allow-list
of safe paths.

---

## MCPA005 — Tool description suggests outbound data flow

**Severity:** medium (variable; `low` for telemetry/hard-coded URLs, `high`
for explicit exfiltration language).
**Maps to:** OWASP MCP Top 10 — Context Over-Sharing.

### What it checks

- Telemetry / analytics / "phone home" language.
- Explicit "send / post / forward / upload (the result|output|data) to <URL>"
  phrasing.
- Hard-coded URLs in tool descriptions (excluding well-known doc/example
  domains).

### Why it matters

Outbound data flow from a tool is also the mechanism a compromised tool would
use to exfiltrate context. Even benign telemetry deserves disclosure.

### Remediation

Document outbound network behavior. Make telemetry opt-in and disclose what
is collected. Avoid hard-coded URLs in tool descriptions; reference docs
instead.

---

## MCPA006 — Remote server auth/scope hygiene

**Severity:** low (variable; `info` for missing metadata, `high` for explicit
broad-scope claims).
**Maps to:** OWASP MCP Top 10 — Insufficient Authentication & Authorization.

### What it checks

For HTTP / Streamable HTTP targets only:

- Whether the server published any metadata (instructions, capabilities) on
  initialize. Missing metadata is informational — it just means we can't
  verify the auth model from the wire.
- Whether the server's published instructions reference broad scopes
  (`admin`, `all scopes`, `*`, `full access`, etc.).

### Why it matters

The MCP Python SDK does not currently expose a scope-aware client API, so
this rule reports informational signals only. A broad declared scope makes
any compromise of the server a privileged compromise.

### Remediation

Document the server's auth model and required scopes in its README. Prefer
per-action scopes (least privilege) over a single broad token.

---

## Adding a new rule

A rule is a 30-line file under `src/mcp_audit/rules/`. See
[`prompt_injection.py`](src/mcp_audit/rules/prompt_injection.py) for a
complete example. The contract:

```python
from mcp_audit.models import Finding, ServerInfo, Severity
from mcp_audit.rules.base import Rule

class MyRule(Rule):
    id = "MCPA999"
    title = "..."
    severity = Severity.MEDIUM
    description = "..."

    def check(self, server_info: ServerInfo) -> list[Finding]:
        ...
```

Drop the file in `src/mcp_audit/rules/`. The registry auto-discovers it.
Add a test file under `tests/test_rules_<your_rule>.py` using the
`make_server_fixture` and `tool_factory` fixtures from `conftest.py`.
