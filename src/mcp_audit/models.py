from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity ranks INFO < LOW < MEDIUM < HIGH < CRITICAL.

    All four ordering ops are defined explicitly because the `str` base
    class supplies its own (lexicographic) comparisons that `functools.
    total_ordering` won't overwrite.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ToolInfo(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)


class ResourceInfo(BaseModel):
    uri: str
    name: str | None = None
    description: str | None = None
    mime_type: str | None = None


class PromptArgument(BaseModel):
    name: str
    description: str | None = None
    required: bool = False


class PromptInfo(BaseModel):
    name: str
    description: str | None = None
    arguments: list[PromptArgument] = Field(default_factory=list)


class Target(BaseModel):
    type: Literal["stdio", "http"]
    value: str


class ServerInfo(BaseModel):
    target: Target
    tools: list[ToolInfo] = Field(default_factory=list)
    resources: list[ResourceInfo] = Field(default_factory=list)
    prompts: list[PromptInfo] = Field(default_factory=list)
    server_metadata: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    """Where in the server we found the issue."""

    kind: Literal["tool", "resource", "prompt", "server"]
    name: str
    field: str | None = None
    snippet: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    title: str
    description: str
    evidence: Evidence
    remediation: str


def severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    return counts
